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
