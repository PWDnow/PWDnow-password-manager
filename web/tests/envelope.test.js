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
