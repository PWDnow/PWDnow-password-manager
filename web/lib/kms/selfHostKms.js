// web/lib/kms/selfHostKms.js
// SelfHostKmsProvider — for small self-host deployments (e.g. a Raspberry Pi 5 serving a
// handful of family/friend accounts) that don't want to run a HashiCorp Vault container just
// for KMS. Wraps/unwraps the per-user DEK with AES-256-GCM under a master key that lives in a
// permission-locked file on disk, optionally itself wrapped by an Argon2id-derived key from an
// admin-supplied passphrase (see loadSelfHostMasterKey / generateSelfHostMasterKeyFile below).
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { statSync, readFileSync, writeFileSync, chmodSync } from 'fs';
import argon2 from 'argon2';

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

// Ties the key-file loader to the provider: the one entry point createKmsProvider (see
// kmsProvider.js) calls for KMS_PROVIDER=selfhost.
export async function createSelfHostKmsProvider({ keyPath, passphrase } = {}) {
  const masterKey = await loadSelfHostMasterKey({ keyPath, passphrase });
  return new SelfHostKmsProvider(masterKey);
}
