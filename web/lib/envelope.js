// web/lib/envelope.js
// Per-user envelope encryption. Owns the KMS and a short-TTL DEK cache.
//   newUserDek()                      → persistable wrapped-DEK fields for a new user row
//   encryptResource(user, value)      → Buffer (iv||tag||ct, AES-256-GCM under the user DEK)
//   decryptResource(user, blob)       → parsed JSON
// DEK buffers live only in pod memory and are zeroized on cache eviction.
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
