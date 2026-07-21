// web/lib/kms/selfHostKms.js
// SelfHostKmsProvider — for small self-host deployments (e.g. a Raspberry Pi 5 serving a
// handful of family/friend accounts) that don't want to run a HashiCorp Vault container just
// for KMS. Wraps/unwraps the per-user DEK with AES-256-GCM under a master key that lives in a
// permission-locked file on disk, optionally itself wrapped by an Argon2id-derived key from an
// admin-supplied passphrase (see loadSelfHostMasterKey / generateSelfHostMasterKeyFile below).
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { statSync, readFileSync, writeFileSync, chmodSync } from 'fs';

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

async function _wrapMasterKeyWithPassphrase(_masterKey, _passphrase) {
  throw new Error('passphrase-wrapped SelfHostKms key files are implemented in Task 4');
}

async function _unwrapMasterKeyWithPassphrase(_raw, _passphrase, _keyPath) {
  throw new Error('passphrase-wrapped SelfHostKms key files are implemented in Task 4');
}
