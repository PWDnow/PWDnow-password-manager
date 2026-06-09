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
