# SelfHostKms Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a third `KmsProvider` implementation — `SelfHostKmsProvider` — that wraps/unwraps
per-user DEKs using a master key file on disk with enforced file permissions and an optional
Argon2id-passphrase-wrapped-at-rest mode, so small self-host deployments (e.g. a Raspberry Pi 5
running for a handful of family/friends) don't need to run a HashiCorp Vault container just for
KMS.

**Architecture:** Same duck-typed `KmsProvider` contract (`wrapDek`/`unwrapDek`) already
satisfied by `LocalDevKmsProvider` and `VaultTransitKmsProvider` — this drops into the existing
`createKmsProvider` factory and the existing `Envelope`/`PostgresVaultRepository` machinery with
zero changes to either. The new surface is entirely in `web/lib/kms/selfHostKms.js`: a key-file
loader/generator with permission + ownership checks, an Argon2id-based passphrase-wrap mode for
the key file itself, and the provider class.

**Tech Stack:** Node.js 24 ESM, Node `crypto` (AES-256-GCM, already used by
`LocalDevKmsProvider`), `argon2` npm package (already a dependency, used elsewhere in
`web/lib/rateLimiter.js`), `node:test`/`node:assert` for tests (existing convention — see
`web/tests/kms.contract.test.js`).

## Global Constraints

- CNSA 2.0 / NIST PQC L5 posture must not be weakened: AES-256-GCM for all wrapping, Argon2id
  for the passphrase KDF — no smaller key sizes, no SHA-256-only KDFs, no reduced Argon2id
  memory/time cost versus what's specified in this plan.
- The `KmsProvider` duck-typed contract (`async wrapDek(dek: Buffer) → { wrapped: Buffer, keyId:
  string }`, `async unwrapDek(wrapped: Buffer, keyId) → Buffer`) must be satisfied exactly as
  documented in `web/lib/kms/kmsProvider.js` — this is what the existing contract test suite
  (`web/tests/kms.contract.test.js`) verifies for every implementation.
- No changes to the Rust daemon, to `LocalDevKmsProvider`, or to `VaultTransitKmsProvider` in
  this plan.
- Follow the existing test convention: plain `node:test`/`node:assert/strict`, run via
  `node --test tests/<file>.js` from `web/`.

---

## File Structure

| File | Responsibility |
|---|---|
| `web/tests/helpers/kmsContractSuite.js` (new) | Shared `kmsContractSuite(label, makeKms)` helper — extracted from `kms.contract.test.js` so it can be reused without re-executing that file's own test registrations. |
| `web/tests/kms.contract.test.js` (modified) | Imports the helper instead of defining it inline; behavior unchanged. |
| `web/lib/kms/selfHostKms.js` (new) | `SelfHostKmsProvider` class, key-file generate/load functions, the `createSelfHostKmsProvider` factory. One file — the key-file format and the provider that consumes it change together. |
| `web/tests/kms.selfhost.contract.test.js` (new) | Contract tests (via the shared helper) + self-host-specific security-property tests (permission checks, passphrase wrapping). |
| `web/lib/kms/kmsProvider.js` (modified) | Add the `selfhost` branch to `createKmsProvider`. |
| `web/.env.example` (modified) | Document `SELF_HOST_KMS_KEY_PATH` / `SELF_HOST_KMS_PASSPHRASE`. |
| `web/scripts/generate-selfhost-kms-key.js` (new) | Standalone CLI to provision a key file (raw or passphrase-wrapped) — usable manually today, callable by the installer later. |

---

### Task 1: Extract the shared KMS contract-test helper

**Files:**
- Create: `web/tests/helpers/kmsContractSuite.js`
- Modify: `web/tests/kms.contract.test.js`

**Interfaces:**
- Produces: `kmsContractSuite(label: string, makeKms: () => Promise<KmsProvider>): void` — registers a `describe` block with 4 `it`s (round-trip, non-plaintext output, tamper rejection, fresh-nonce non-determinism) against whatever `KmsProvider`-shaped object `makeKms()` resolves to.

- [ ] **Step 1: Create the helper module**

Create `web/tests/helpers/kmsContractSuite.js` with exactly the current contents of the
`kmsContractSuite` function from `web/tests/kms.contract.test.js`:

```javascript
// web/tests/helpers/kmsContractSuite.js
// Shared KmsProvider contract suite. Import this (not kms.contract.test.js) from any test file
// that wants to verify a new KmsProvider implementation — importing a .test.js file directly
// would re-execute its own top-level describe() registrations too.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'crypto';

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
```

- [ ] **Step 2: Update `kms.contract.test.js` to import the helper**

Replace the full contents of `web/tests/kms.contract.test.js` with:

```javascript
// web/tests/kms.contract.test.js
import { randomBytes } from 'crypto';
import { kmsContractSuite } from './helpers/kmsContractSuite.js';
import { LocalDevKmsProvider } from '../lib/kms/localDevKms.js';

kmsContractSuite('LocalDev', async () => new LocalDevKmsProvider(randomBytes(32)));

if (process.env.VAULT_ADDR && process.env.VAULT_TOKEN && process.env.VAULT_TRANSIT_KEY) {
  const { VaultTransitKmsProvider } = await import('../lib/kms/vaultTransitKms.js');
  kmsContractSuite('VaultTransit', async () => new VaultTransitKmsProvider({
    addr: process.env.VAULT_ADDR, token: process.env.VAULT_TOKEN, keyName: process.env.VAULT_TRANSIT_KEY,
  }));
}
```

- [ ] **Step 3: Run — expect pass, identical test count to before**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.contract.test.js
```
Expected: `KmsProvider contract — LocalDev` suite, 4 tests, all PASS. (VaultTransit suite skipped —
no env vars set in this environment. Same as before the refactor.)

- [ ] **Step 4: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add tests/helpers/kmsContractSuite.js tests/kms.contract.test.js
git commit -m "refactor(kms): extract shared kmsContractSuite helper for reuse by new providers"
```

---

### Task 2: `SelfHostKmsProvider` class (wrap/unwrap only)

**Files:**
- Create: `web/lib/kms/selfHostKms.js`
- Test: `web/tests/kms.selfhost.contract.test.js`

**Interfaces:**
- Consumes: `kmsContractSuite` from `./helpers/kmsContractSuite.js` (Task 1).
- Produces: `class SelfHostKmsProvider { constructor(masterKey: Buffer); async wrapDek(dek: Buffer); async unwrapDek(wrapped: Buffer, keyId: string); }` — consumed by Task 5's factory and Task 6's wiring.

- [ ] **Step 1: Write the failing test**

Create `web/tests/kms.selfhost.contract.test.js`:

```javascript
// web/tests/kms.selfhost.contract.test.js
import { randomBytes } from 'crypto';
import { kmsContractSuite } from './helpers/kmsContractSuite.js';
import { SelfHostKmsProvider } from '../lib/kms/selfHostKms.js';

kmsContractSuite('SelfHost (direct key)', async () => new SelfHostKmsProvider(randomBytes(32)));
```

- [ ] **Step 2: Run — expect failure**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.selfhost.contract.test.js
```
Expected: FAIL — cannot find `../lib/kms/selfHostKms.js`.

- [ ] **Step 3: Implement `SelfHostKmsProvider`**

Create `web/lib/kms/selfHostKms.js`:

```javascript
// web/lib/kms/selfHostKms.js
// SelfHostKmsProvider — for small self-host deployments (e.g. a Raspberry Pi 5 serving a
// handful of family/friend accounts) that don't want to run a HashiCorp Vault container just
// for KMS. Wraps/unwraps the per-user DEK with AES-256-GCM under a master key that lives in a
// permission-locked file on disk, optionally itself wrapped by an Argon2id-derived key from an
// admin-supplied passphrase (see loadSelfHostMasterKey / generateSelfHostMasterKeyFile below).
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

export class SelfHostKmsProvider {
  constructor(masterKey) {
    if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
      throw new Error('SelfHostKmsProvider requires a 32-byte key');
    }
    this._key = masterKey;
    this._keyId = 'selfhost:v1';
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
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.selfhost.contract.test.js
```
Expected: `KmsProvider contract — SelfHost (direct key)` suite, 4 tests, all PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/kms/selfHostKms.js tests/kms.selfhost.contract.test.js
git commit -m "feat(kms): SelfHostKmsProvider wrap/unwrap (direct-key contract passing)"
```

---

### Task 3: Master-key file — generate + load (raw, no passphrase), with permission/ownership checks

**Files:**
- Modify: `web/lib/kms/selfHostKms.js`
- Modify: `web/tests/kms.selfhost.contract.test.js`

**Interfaces:**
- Produces: `async function generateSelfHostMasterKeyFile({ keyPath: string, passphrase?: string }): Promise<void>`, `async function loadSelfHostMasterKey({ keyPath: string, passphrase?: string }): Promise<Buffer>` — consumed by Task 5's factory.

- [ ] **Step 1: Write failing tests**

Append to `web/tests/kms.selfhost.contract.test.js`:

```javascript
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, chmodSync, writeFileSync, statSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import {
  generateSelfHostMasterKeyFile,
  loadSelfHostMasterKey,
} from '../lib/kms/selfHostKms.js';

describe('SelfHostKms master-key file (raw, no passphrase)', () => {
  let dir;
  const cleanupDirs = [];
  function newDir() {
    const d = mkdtempSync(path.join(tmpdir(), 'selfhost-kms-'));
    cleanupDirs.push(d);
    return d;
  }
  after(() => { for (const d of cleanupDirs) rmSync(d, { recursive: true, force: true }); });

  it('generate then load round-trips a 32-byte key', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath });
    const key = await loadSelfHostMasterKey({ keyPath });
    assert.ok(Buffer.isBuffer(key));
    assert.equal(key.length, 32);
  });

  it('generated file is created with mode 0600', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath });
    const mode = statSync(keyPath).mode & 0o777;
    assert.equal(mode, 0o600);
  });

  it('refuses to load a group-readable key file', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath });
    chmodSync(keyPath, 0o640);
    await assert.rejects(() => loadSelfHostMasterKey({ keyPath }), /group\/world readable/);
  });

  it('refuses to load a world-readable key file', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath });
    chmodSync(keyPath, 0o644);
    await assert.rejects(() => loadSelfHostMasterKey({ keyPath }), /group\/world readable/);
  });

  it('refuses to load a file that is not exactly 32 bytes', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'bad.key');
    writeFileSync(keyPath, Buffer.from('too short'), { mode: 0o600 });
    await assert.rejects(() => loadSelfHostMasterKey({ keyPath }), /32 bytes/);
  });
});
```

- [ ] **Step 2: Run — expect failure**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.selfhost.contract.test.js
```
Expected: FAIL — `generateSelfHostMasterKeyFile is not a function` (or similar import error).

- [ ] **Step 3: Implement the loader/generator**

Append to `web/lib/kms/selfHostKms.js` (after the imports at the top, add `statSync`,
`readFileSync`, `writeFileSync`, `chmodSync` to the `fs` import; add the two functions after the
`SelfHostKmsProvider` class):

Update the top of the file:
```javascript
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { statSync, readFileSync, writeFileSync, chmodSync } from 'fs';
```

Add after the `SelfHostKmsProvider` class:
```javascript
// Provisions a fresh 32-byte master key file. `passphrase` support is added in a later task —
// this raw-key path writes the 32 bytes directly, mode 0600.
export async function generateSelfHostMasterKeyFile({ keyPath, passphrase } = {}) {
  if (!keyPath) throw new Error('generateSelfHostMasterKeyFile requires keyPath');
  const masterKey = randomBytes(32);
  const fileBytes = passphrase ? await _wrapMasterKeyWithPassphrase(masterKey, passphrase) : masterKey;
  writeFileSync(keyPath, fileBytes, { mode: 0o600 });
  chmodSync(keyPath, 0o600); // belt-and-suspenders: umask can affect the mode writeFileSync requested
}

// Loads and verifies the master key file: rejects group/world-readable files and files not
// owned by the running user, then returns the raw 32-byte key (unwrapping the passphrase layer
// first if `passphrase` is supplied).
export async function loadSelfHostMasterKey({ keyPath, passphrase } = {}) {
  if (!keyPath) throw new Error('loadSelfHostMasterKey requires keyPath');
  const st = statSync(keyPath);
  if (st.mode & 0o077) {
    throw new Error(`SelfHostKms key file ${keyPath} must not be group/world readable (mode ${(st.mode & 0o777).toString(8)})`);
  }
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new Error(`SelfHostKms key file ${keyPath} must be owned by the running user (uid ${process.getuid()}), found uid ${st.uid}`);
  }
  const raw = readFileSync(keyPath);
  if (!passphrase) {
    if (raw.length !== 32) {
      throw new Error(`SelfHostKms key file ${keyPath} must be exactly 32 bytes (got ${raw.length}) when no passphrase is used`);
    }
    return raw;
  }
  return _unwrapMasterKeyWithPassphrase(raw, passphrase, keyPath);
}
```

Add placeholder-free stand-ins for the two passphrase helpers so the file is valid and this
task's (no-passphrase) tests pass without depending on Task 4's Argon2id work yet:

```javascript
async function _wrapMasterKeyWithPassphrase(_masterKey, _passphrase) {
  throw new Error('passphrase-wrapped SelfHostKms key files are implemented in Task 4');
}

async function _unwrapMasterKeyWithPassphrase(_raw, _passphrase, _keyPath) {
  throw new Error('passphrase-wrapped SelfHostKms key files are implemented in Task 4');
}
```

- [ ] **Step 4: Run — expect pass**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.selfhost.contract.test.js
```
Expected: all tests in both describe blocks PASS (9 tests total: 4 contract + 5 new).

- [ ] **Step 5: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/kms/selfHostKms.js tests/kms.selfhost.contract.test.js
git commit -m "feat(kms): SelfHostKms master-key file generate/load with permission+ownership checks"
```

---

### Task 4: Passphrase-wrapped master key via Argon2id

**Files:**
- Modify: `web/lib/kms/selfHostKms.js`
- Modify: `web/tests/kms.selfhost.contract.test.js`

**Interfaces:**
- Consumes: `argon2` package (`import argon2 from 'argon2'`), already a dependency (used in `web/lib/rateLimiter.js:2`).
- Produces: real implementations of `_wrapMasterKeyWithPassphrase` / `_unwrapMasterKeyWithPassphrase` (internal, not exported) that `generateSelfHostMasterKeyFile`/`loadSelfHostMasterKey` from Task 3 already call.

- [ ] **Step 1: Write failing tests**

Append to `web/tests/kms.selfhost.contract.test.js`:

```javascript
describe('SelfHostKms master-key file (passphrase-wrapped)', () => {
  let dir;
  const cleanupDirs = [];
  function newDir() {
    const d = mkdtempSync(path.join(tmpdir(), 'selfhost-kms-pw-'));
    cleanupDirs.push(d);
    return d;
  }
  after(() => { for (const d of cleanupDirs) rmSync(d, { recursive: true, force: true }); });

  it('generate then load with the correct passphrase round-trips a 32-byte key', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath, passphrase: 'correct horse battery staple' });
    const key = await loadSelfHostMasterKey({ keyPath, passphrase: 'correct horse battery staple' });
    assert.ok(Buffer.isBuffer(key));
    assert.equal(key.length, 32);
  });

  it('the same master key is recovered as would be with a raw (non-passphrase) file of the same content', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath, passphrase: 'hunter2-hunter2-hunter2' });
    const a = await loadSelfHostMasterKey({ keyPath, passphrase: 'hunter2-hunter2-hunter2' });
    const b = await loadSelfHostMasterKey({ keyPath, passphrase: 'hunter2-hunter2-hunter2' });
    assert.ok(a.equals(b), 'loading twice with the same passphrase must yield the same key');
  });

  it('wrong passphrase fails to unwrap', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath, passphrase: 'right-passphrase' });
    await assert.rejects(() => loadSelfHostMasterKey({ keyPath, passphrase: 'wrong-passphrase' }));
  });

  it('passphrase-wrapped file is still mode 0600', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath, passphrase: 'whatever' });
    assert.equal(statSync(keyPath).mode & 0o777, 0o600);
  });

  it('resulting provider round-trips a DEK end to end', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath, passphrase: 'end-to-end-check' });
    const masterKey = await loadSelfHostMasterKey({ keyPath, passphrase: 'end-to-end-check' });
    const kms = new SelfHostKmsProvider(masterKey);
    const dek = randomBytes(32);
    const { wrapped, keyId } = await kms.wrapDek(dek);
    assert.ok((await kms.unwrapDek(wrapped, keyId)).equals(dek));
  });
});
```

- [ ] **Step 2: Run — expect failure**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.selfhost.contract.test.js
```
Expected: FAIL on the new `describe` block — the two `_wrap/_unwrapMasterKeyWithPassphrase`
stubs throw "implemented in Task 4".

- [ ] **Step 3: Implement Argon2id passphrase wrapping**

In `web/lib/kms/selfHostKms.js`: add the `argon2` import at the top —

```javascript
import argon2 from 'argon2';
```

Replace the two stub functions from Task 3 with:

```javascript
// Argon2id params for wrapping the master key file under a passphrase. This runs once at
// process start (not on an interactive hot path), so cost is set high: 256 MiB / t=3 / p=1 —
// matching the params already used for this codebase's other high-value, infrequent KDF use
// (duress-mode password hashing in src/utils/securityModes.ts).
const SELF_HOST_KDF_OPTS = {
  type: argon2.argon2id,
  memoryCost: 262144, // 256 MiB, in KiB
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
  raw: true,
};

// File layout when passphrase-wrapped: salt(16) || iv(12) || tag(16) || ciphertext(32) = 76 bytes.
async function _wrapMasterKeyWithPassphrase(masterKey, passphrase) {
  const salt = randomBytes(16);
  const kek = await argon2.hash(passphrase, { ...SELF_HOST_KDF_OPTS, salt });
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', kek, iv);
  const ct = Buffer.concat([c.update(masterKey), c.final()]);
  const tag = c.getAuthTag();
  return Buffer.concat([salt, iv, tag, ct]);
}

async function _unwrapMasterKeyWithPassphrase(raw, passphrase, keyPath) {
  if (raw.length !== 76) {
    throw new Error(`SelfHostKms passphrase-wrapped key file ${keyPath} must be exactly 76 bytes (got ${raw.length})`);
  }
  const salt = raw.subarray(0, 16);
  const iv = raw.subarray(16, 28);
  const tag = raw.subarray(28, 44);
  const ct = raw.subarray(44, 76);
  const kek = await argon2.hash(passphrase, { ...SELF_HOST_KDF_OPTS, salt });
  const d = createDecipheriv('aes-256-gcm', kek, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}
```

Also update `loadSelfHostMasterKey`'s no-passphrase length check so a passphrase-wrapped file
(76 bytes) given without a passphrase fails with a clear message rather than the generic "must
be exactly 32 bytes" — find this block from Task 3:

```javascript
  if (!passphrase) {
    if (raw.length !== 32) {
      throw new Error(`SelfHostKms key file ${keyPath} must be exactly 32 bytes (got ${raw.length}) when no passphrase is used`);
    }
    return raw;
  }
```

and leave it as-is — the existing message already reports the actual byte count, which is
sufficient to diagnose a 76-vs-32 mismatch. No change needed here; this note exists so the
implementer doesn't "fix" something that isn't broken.

- [ ] **Step 4: Run — expect pass**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.selfhost.contract.test.js
```
Expected: all tests across all three describe blocks PASS (14 tests total).

- [ ] **Step 5: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/kms/selfHostKms.js tests/kms.selfhost.contract.test.js
git commit -m "feat(kms): Argon2id passphrase-wrapped SelfHostKms master-key file mode"
```

---

### Task 5: `createSelfHostKmsProvider` factory (loader + provider tied together)

**Files:**
- Modify: `web/lib/kms/selfHostKms.js`
- Modify: `web/tests/kms.selfhost.contract.test.js`

**Interfaces:**
- Produces: `async function createSelfHostKmsProvider({ keyPath: string, passphrase?: string }): Promise<SelfHostKmsProvider>` — this is what Task 6 wires into `createKmsProvider`.

- [ ] **Step 1: Write failing tests**

Append to `web/tests/kms.selfhost.contract.test.js`:

```javascript
import { createSelfHostKmsProvider } from '../lib/kms/selfHostKms.js';

kmsContractSuite('SelfHost (factory, no passphrase)', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'selfhost-kms-factory-'));
  const keyPath = path.join(dir, 'master.key');
  await generateSelfHostMasterKeyFile({ keyPath });
  return createSelfHostKmsProvider({ keyPath });
});

kmsContractSuite('SelfHost (factory, passphrase)', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'selfhost-kms-factory-pw-'));
  const keyPath = path.join(dir, 'master.key');
  const passphrase = 'factory-suite-passphrase';
  await generateSelfHostMasterKeyFile({ keyPath, passphrase });
  return createSelfHostKmsProvider({ keyPath, passphrase });
});
```

- [ ] **Step 2: Run — expect failure**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.selfhost.contract.test.js
```
Expected: FAIL — `createSelfHostKmsProvider is not a function` (or import error).

- [ ] **Step 3: Implement the factory**

Add to the end of `web/lib/kms/selfHostKms.js`:

```javascript
// Ties the key-file loader to the provider: the one entry point createKmsProvider (see
// kmsProvider.js) calls for KMS_PROVIDER=selfhost.
export async function createSelfHostKmsProvider({ keyPath, passphrase } = {}) {
  const masterKey = await loadSelfHostMasterKey({ keyPath, passphrase });
  return new SelfHostKmsProvider(masterKey);
}
```

- [ ] **Step 4: Run — expect pass**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.selfhost.contract.test.js
```
Expected: all suites PASS — 5 `describe` blocks (contract×3 + security-property×2), 22 tests total.

- [ ] **Step 5: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/kms/selfHostKms.js tests/kms.selfhost.contract.test.js
git commit -m "feat(kms): createSelfHostKmsProvider factory (loader + provider)"
```

---

### Task 6: Wire `KMS_PROVIDER=selfhost` into `createKmsProvider` + document env vars

**Files:**
- Modify: `web/lib/kms/kmsProvider.js`
- Modify: `web/.env.example`
- Test: `web/tests/kms.selfhost.contract.test.js` (add one more case, going through the real factory entry point)

**Interfaces:**
- Consumes: `createSelfHostKmsProvider` from `./selfHostKms.js` (Task 5).

- [ ] **Step 1: Write the failing test**

Append to `web/tests/kms.selfhost.contract.test.js`:

```javascript
import { createKmsProvider } from '../lib/kms/kmsProvider.js';

describe('createKmsProvider(KMS_PROVIDER=selfhost)', () => {
  it('builds a working SelfHostKmsProvider from env vars', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'selfhost-kms-env-'));
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath });

    const prevProvider = process.env.KMS_PROVIDER;
    const prevKeyPath = process.env.SELF_HOST_KMS_KEY_PATH;
    process.env.KMS_PROVIDER = 'selfhost';
    process.env.SELF_HOST_KMS_KEY_PATH = keyPath;
    try {
      const kms = await createKmsProvider();
      const dek = randomBytes(32);
      const { wrapped, keyId } = await kms.wrapDek(dek);
      assert.ok((await kms.unwrapDek(wrapped, keyId)).equals(dek));
    } finally {
      process.env.KMS_PROVIDER = prevProvider;
      if (prevKeyPath === undefined) delete process.env.SELF_HOST_KMS_KEY_PATH;
      else process.env.SELF_HOST_KMS_KEY_PATH = prevKeyPath;
    }
  });

  it('throws a clear error when SELF_HOST_KMS_KEY_PATH is missing', async () => {
    const prevProvider = process.env.KMS_PROVIDER;
    const prevKeyPath = process.env.SELF_HOST_KMS_KEY_PATH;
    process.env.KMS_PROVIDER = 'selfhost';
    delete process.env.SELF_HOST_KMS_KEY_PATH;
    try {
      await assert.rejects(() => createKmsProvider(), /SELF_HOST_KMS_KEY_PATH/);
    } finally {
      process.env.KMS_PROVIDER = prevProvider;
      if (prevKeyPath !== undefined) process.env.SELF_HOST_KMS_KEY_PATH = prevKeyPath;
    }
  });
});
```

- [ ] **Step 2: Run — expect failure**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.selfhost.contract.test.js
```
Expected: FAIL — `createKmsProvider` throws `unknown KMS_PROVIDER: selfhost` instead of building
a provider (first test); second test not yet reachable / also failing for the wrong reason.

- [ ] **Step 3: Add the `selfhost` branch**

In `web/lib/kms/kmsProvider.js`, add a branch before the final `throw`:

```javascript
  if (kind === 'selfhost') {
    return import('./selfHostKms.js').then(({ createSelfHostKmsProvider }) => {
      const keyPath = process.env.SELF_HOST_KMS_KEY_PATH;
      if (!keyPath) {
        throw new Error('SELF_HOST_KMS_KEY_PATH is required when KMS_PROVIDER=selfhost');
      }
      return createSelfHostKmsProvider({ keyPath, passphrase: process.env.SELF_HOST_KMS_PASSPHRASE || undefined });
    });
  }
```

Also update the file's header comment (`// Implementations: LocalDevKmsProvider (dev/CI),
VaultTransitKmsProvider (default prod).`) to:

```javascript
// Implementations: LocalDevKmsProvider (dev/CI), VaultTransitKmsProvider (default prod),
// SelfHostKmsProvider (small self-host, e.g. Raspberry Pi 5 — see selfHostKms.js).
```

- [ ] **Step 4: Run — expect pass**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.selfhost.contract.test.js
```
Expected: all PASS, including both new `createKmsProvider(KMS_PROVIDER=selfhost)` tests.

- [ ] **Step 5: Document the env vars**

In `web/.env.example`, find the existing KMS block:

```
# KMS_PROVIDER: local (dev/CI) | vault (HashiCorp Vault Transit, default prod)
KMS_PROVIDER=local
LOCAL_KMS_KEY=          # 32-byte hex, required when KMS_PROVIDER=local
VAULT_ADDR=https://vault.internal:8200
VAULT_TOKEN=
VAULT_TRANSIT_KEY=pwdnow-dek
```

Replace it with:

```
# KMS_PROVIDER: local (dev/CI) | vault (HashiCorp Vault Transit, default prod) | selfhost (small self-host, e.g. Raspberry Pi 5)
KMS_PROVIDER=local
LOCAL_KMS_KEY=          # 32-byte hex, required when KMS_PROVIDER=local
VAULT_ADDR=https://vault.internal:8200
VAULT_TOKEN=
VAULT_TRANSIT_KEY=pwdnow-dek
SELF_HOST_KMS_KEY_PATH=  # path to the master key file, required when KMS_PROVIDER=selfhost — provision with: node scripts/generate-selfhost-kms-key.js
SELF_HOST_KMS_PASSPHRASE=  # optional — set only if the key file was generated with --passphrase
```

- [ ] **Step 6: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/kms/kmsProvider.js tests/kms.selfhost.contract.test.js .env.example
git commit -m "feat(kms): wire KMS_PROVIDER=selfhost into createKmsProvider; document env vars"
```

---

### Task 7: Standalone provisioning CLI + full regression

**Files:**
- Create: `web/scripts/generate-selfhost-kms-key.js`

**Interfaces:**
- Consumes: `generateSelfHostMasterKeyFile` from `../lib/kms/selfHostKms.js` (Task 3).

This script is intentionally decoupled from `install.sh` — it's a plain Node CLI the installer
(or an admin) can call later; wiring it into the interactive installer flow is out of scope for
this plan (see the design spec, §3b/§7).

- [ ] **Step 1: Write the script**

Create `web/scripts/generate-selfhost-kms-key.js`:

```javascript
#!/usr/bin/env node
// web/scripts/generate-selfhost-kms-key.js
// Provisions a SelfHostKms master key file. Usage:
//   node scripts/generate-selfhost-kms-key.js --path /var/lib/pwdnow/kms-master.key [--passphrase]
//
// --passphrase prompts for a passphrase (twice, must match) on stderr without echoing, and
// wraps the master key under it (Argon2id). Without --passphrase, the key file is raw bytes —
// simpler, but the whole security of the KMS layer then rests on file permissions alone.
import { generateSelfHostMasterKeyFile } from '../lib/kms/selfHostKms.js';
import { createInterface } from 'readline';
import { existsSync } from 'fs';

function readHidden(prompt) {
  return new Promise((resolve) => {
    process.stderr.write(prompt);
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    // Node's readline has no built-in hidden-input mode; muting output writes is the standard
    // workaround for a simple CLI prompt like this one.
    const onWrite = rl._writeToOutput;
    rl._writeToOutput = () => {};
    rl.question('', (answer) => {
      rl._writeToOutput = onWrite;
      rl.history = rl.history.slice(1);
      process.stderr.write('\n');
      rl.close();
      resolve(answer);
    });
  });
}

async function main() {
  const args = process.argv.slice(2);
  const pathIdx = args.indexOf('--path');
  const keyPath = pathIdx !== -1 ? args[pathIdx + 1] : null;
  const usePassphrase = args.includes('--passphrase');

  if (!keyPath) {
    console.error('Usage: node scripts/generate-selfhost-kms-key.js --path <file> [--passphrase]');
    process.exit(1);
  }
  if (existsSync(keyPath)) {
    console.error(`Refusing to overwrite existing file: ${keyPath}`);
    process.exit(1);
  }

  let passphrase;
  if (usePassphrase) {
    const a = await readHidden('Passphrase: ');
    const b = await readHidden('Confirm passphrase: ');
    if (a !== b) {
      console.error('Passphrases did not match.');
      process.exit(1);
    }
    if (a.length < 12) {
      console.error('Passphrase must be at least 12 characters.');
      process.exit(1);
    }
    passphrase = a;
  }

  await generateSelfHostMasterKeyFile({ keyPath, passphrase });
  console.error(`Wrote SelfHostKms master key to ${keyPath} (mode 0600).`);
  console.error('Set in web/.env:');
  console.error('  KMS_PROVIDER=selfhost');
  console.error(`  SELF_HOST_KMS_KEY_PATH=${keyPath}`);
  if (usePassphrase) console.error('  SELF_HOST_KMS_PASSPHRASE=<the passphrase you just entered>');
}

main();
```

- [ ] **Step 2: Smoke-test the script manually**

```bash
cd /home/pwd-vm/PWDnow/web && node scripts/generate-selfhost-kms-key.js --path /tmp/pwdnow-selfhost-smoketest.key
ls -l /tmp/pwdnow-selfhost-smoketest.key
```
Expected: script prints the "Wrote SelfHostKms master key..." message and the follow-up env
vars; `ls -l` shows `-rw-------` (mode 600) and file size 32 bytes.

```bash
rm -f /tmp/pwdnow-selfhost-smoketest.key
```

- [ ] **Step 3: Full regression — whole KMS test surface + lint**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.contract.test.js tests/kms.selfhost.contract.test.js tests/envelope.test.js && npm run lint
```
Expected: all tests pass; `tsc --noEmit` clean. (`envelope.test.js` is included because it
exercises `Envelope` against `LocalDevKmsProvider` — this confirms the Task 1 refactor didn't
disturb anything Envelope depends on.)

- [ ] **Step 4: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add scripts/generate-selfhost-kms-key.js
git commit -m "feat(kms): standalone SelfHostKms master-key provisioning CLI"
```

---

## Follow-up (explicitly out of scope for this plan)

- Wiring `KMS_PROVIDER=selfhost` as the interactive installer's default choice in `install.sh`
  for a "small self-host" profile — `install.sh` is a large, separate interactive script;
  touching it belongs in its own reviewed change once this provider exists and is merged.
- `device_grants` schema, access-token store, and the browser-extension pairing/refresh/revoke
  endpoints (P-Ext-A in the design spec) — separate plan.
- Daemon-side `IssueExtensionGrant`/`RefreshExtensionGrant`/`RevokeExtensionGrant` IPC (P-Ext-B)
  — separate plan, Rust codebase.
- The browser extension itself (P-Ext-C) — separate project at `~/Documents/PWDnow_extension`.
