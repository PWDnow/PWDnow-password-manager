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
