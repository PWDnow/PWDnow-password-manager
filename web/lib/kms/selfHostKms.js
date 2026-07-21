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
