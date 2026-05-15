/** @vitest-environment jsdom */
import { describe, it, expect, beforeEach } from 'vitest';
import { writeEncryptedLocal, readDecryptedLocal } from './localCrypto';
import { keyStore, deriveLocalKeys } from '../crypto/keystore';

describe('LocalCryptoEnvelope v2 (Argon2id)', () => {
  const password = 'TestPassword123!';
  const salt = '0123456789abcdef0123456789abcdef';
  const token = 'session-token-abc';

  // Use smaller parameters for tests to avoid timeout
  // NOTE: In a real test we might want to test the real params, but here we just want to verify logic.
  // Since we can't easily change the const in keystore.ts without redeclaring,
  // we'll just accept the time or mock argon2id.

  beforeEach(async () => {
    localStorage.clear();
    keyStore.clear();
    // We skip the real deriveLocalKeys if it's too slow, but let's try it once.
    // If it's too slow, we'll mock it.
    const { v1, v2 } = await deriveLocalKeys(password, salt, token);
    keyStore.storeLocalKey(v1.encKey, 1);
    keyStore.storeSigningKey(v1.sigKey, 1);
    if (v2) {
      keyStore.storeLocalKey(v2.encKey, 2);
      keyStore.storeSigningKey(v2.sigKey, 2);
      const saltBytes = Uint8Array.from(salt.match(/../g)!.map(h => parseInt(h, 16)));
      keyStore.setV2Salt(saltBytes);
    }
  }, 60000); // 60s timeout for Argon2

  it('should write and read back a v2 token', async () => {
    const key = 'test_item';
    const value = JSON.stringify({ hello: 'world' });
    await writeEncryptedLocal(key, value);
    
    const stored = localStorage.getItem(key);
    expect(stored).toContain('lcv2.');
    
    const read = await readDecryptedLocal(key);
    expect(read).toBe(value);
  });

  it('should be unreadable if session token changes', async () => {
     const key = 'session_bound_item';
     const value = 'secret';
     await writeEncryptedLocal(key, value);
     
     // Change session token (derives new v2 key)
     const { v2 } = await deriveLocalKeys(password, salt, 'different-token');
     keyStore.storeLocalKey(v2!.encKey, 2);
     keyStore.storeSigningKey(v2!.sigKey, 2);
     
     const read = await readDecryptedLocal(key);
     expect(read).toBeNull(); 
  }, 60000);

  it('should read back a v1 token (backward compatibility)', async () => {
    const key = 'legacy_item';
    const value = 'legacy_value';
    
    // Manually create a v1 token
    const ck1 = keyStore.getLocalKey(1)!;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, ck1, new TextEncoder().encode(value)));
    const payload = new Uint8Array(iv.length + ct.length);
    payload.set(iv); payload.set(ct, 12);
    
    const toB64u = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    
    const b64payload = toB64u(payload);
    const headerJSON = JSON.stringify({ v: '1', alg: 'A256GCM+HS256' });
    const headerB64 = toB64u(new TextEncoder().encode(headerJSON));
    
    const sk1 = keyStore.getSigningKey(1)!;
    const sigInput = new TextEncoder().encode(`${headerB64}.${b64payload}`);
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', sk1, sigInput));
    const sigB64 = toB64u(sig);
    
    localStorage.setItem(key, `${headerB64}.${b64payload}.${sigB64}`);
    
    const read = await readDecryptedLocal(key);
    expect(read).toBe(value);
  });
});
