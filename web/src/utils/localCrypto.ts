import { logger } from './logger';
import { keyStore, V2_M_LOG2, V2_T, V2_P } from '../crypto/keystore';

// ── Compact token format ──────────────────────────────────────────────────────
//
// All localStorage values are written as a 3-part dot-separated compact token
// (analogous to JWE compact serialization):
//
//   BASE64URL(header) . BASE64URL(iv || ciphertext) . BASE64URL(hmac_sig)
//
// header    : static JSON {"v":"1","alg":"A256GCM+HS256"} - identifies the scheme
// iv||ct    : 12-byte AES-GCM IV concatenated with the GCM ciphertext+tag
// hmac_sig  : HMAC-SHA256 over "header.payload" using the session signing key
//
// AES-GCM provides authenticated encryption (the 16-byte GCM tag is itself a MAC).
// The outer HMAC-SHA256 adds a second independent authentication layer using a key
// derived from the same PBKDF2 pass as the encryption key but from a different
// 32-byte block - defense in depth against GCM nonce-reuse or implementation bugs.
//
// Legacy format support: existing blobs written as {"enc":1,"iv":"...","ct":"..."}
// JSON are still decrypted transparently (no migration script needed).

const V2_PREFIX = 'lcv2.';
const V2_VERSION = 0x02;

const HDR_B64 = (() => {
  const json = JSON.stringify({ v: '1', alg: 'A256GCM+HS256' });
  return btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
})();

function toB64u(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64u(s: string): Uint8Array {
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

/**
 * Encrypt `value` (JSON string) with AES-GCM-256, sign with HMAC-SHA256, and
 * write the compact token to localStorage under `key`.
 * Silently returns without writing if the session keys are not in memory -
 * vault data is NEVER written in plaintext under any circumstances.
 */
export async function encryptForServer(value: string): Promise<string | null> {
  // Server-stored vault data MUST use the deterministic v1 (PBKDF2) key.
  // The v2 (Argon2id) key incorporates a per-session random token that changes
  // on every login, making data encrypted with v2 unrecoverable after re-login.
  await keyStore.restoreAsync();
  const ck = keyStore.getLocalKey(1);
  if (!ck) {
    // Caller (`_localWrite`) translates this into a thrown error so the UI
    // can roll back. No console noise - the user already gets a notification.
    return null;
  }
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, ck, new TextEncoder().encode(value)),
    );
    const payload = new Uint8Array(iv.length + ct.length);
    payload.set(iv);
    payload.set(ct, iv.length);
    return toB64u(payload);
  } catch (e) { 
    logger.error('[localCrypto] encryptForServer failed:', e);
    return null; 
  }
}

export async function decryptFromServer(token: string): Promise<string | null> {
  try {
    if (!token) return null;
    // Transparent pass-through if it looks like raw JSON array/object (for legacy migration)
    if (token.startsWith('[') || token.startsWith('{')) return token;

    await keyStore.restoreAsync();

    // Decrypt fallback chain:
    //   1. v1 (PBKDF2 derived from the server-authoritative cryptoSalt) - the
    //      canonical key for server-stored data going forward.
    //   2. legacy v1 (PBKDF2 derived from a stale local `_lk_salt`) - only set
    //      at login when an old random local salt is detected. This unblocks
    //      accounts whose data was encrypted before the salt-rebind fix.
    //   3. v2 (Argon2id) - only valid within the same session that wrote it
    //      (the v2 key is bound to a per-session token).
    const candidates: Array<CryptoKey | null> = [
      keyStore.getLocalKey(1),
      keyStore.getLegacyKey(),
      keyStore.getLocalKey(2),
    ];
    const ivCt = fromB64u(token);
    const iv = ivCt.slice(0, 12);
    const ct = ivCt.slice(12);
    for (const ck of candidates) {
      if (!ck) continue;
      try {
        return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, ck, ct));
      } catch { continue; }
    }
    return null;
  } catch (e) { 
    logger.error('[localCrypto] decryptFromServer failed:', e);
    return null; 
  }
}

export async function writeEncryptedLocal(key: string, value: string): Promise<void> {
  if (keyStore.v2Pending) await keyStore.v2Pending;
  const ck2 = keyStore.getLocalKey(2);
  const salt = keyStore.getV2Salt();

  if (ck2 && salt) {
    try {
      const header = new Uint8Array(21);
      header[0] = V2_VERSION;
      header.set(salt, 1);
      header[17] = V2_M_LOG2;
      header[18] = V2_T;
      header[19] = V2_P;
      header[20] = 0x00;
      const headerB64 = toB64u(header);

      const iv = crypto.getRandomValues(new Uint8Array(12));
      const aad = new Uint8Array(header.length + key.length);
      aad.set(header);
      aad.set(new TextEncoder().encode(key), header.length);

      const ct = new Uint8Array(
        await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, ck2, new TextEncoder().encode(value)),
      );

      const ivCt = new Uint8Array(iv.length + ct.length);
      ivCt.set(iv);
      ivCt.set(ct, iv.length);
      const payloadB64 = toB64u(ivCt);

      const sk = keyStore.getSigningKey(2);
      let token = `${V2_PREFIX}${headerB64}.${payloadB64}`;
      if (sk) {
        const sigInput = new TextEncoder().encode(token);
        const sig = new Uint8Array(await crypto.subtle.sign('HMAC', sk, sigInput));
        token += `.${toB64u(sig)}`;
      }
      localStorage.setItem(key, token);
      return;
    } catch (e) {
      logger.error('[localCrypto] v2 write failed:', e);
    }
  }

  // ── Fallback to v1 (PBKDF2) ─────────────────────────────────────────────
  const ck1 = keyStore.getLocalKey(1);
  if (!ck1) return; // No key - refuse to write plaintext. Wait for login.
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, ck1, new TextEncoder().encode(value)),
    );

    // Payload: IV (12 B) || ciphertext+tag (variable)
    const payload = new Uint8Array(iv.length + ct.length);
    payload.set(iv);
    payload.set(ct, iv.length);
    const b64payload = toB64u(payload);

    const sk = keyStore.getSigningKey(1);
    let token: string;
    if (sk) {
      const sigInput = new TextEncoder().encode(`${HDR_B64}.${b64payload}`);
      const sig = new Uint8Array(await crypto.subtle.sign('HMAC', sk, sigInput));
      token = `${HDR_B64}.${b64payload}.${toB64u(sig)}`;
    } else {
      token = `${HDR_B64}.${b64payload}`;
    }
    localStorage.setItem(key, token);
  } catch { /* storage quota / private mode - non-fatal */ }
}

/**
 * Read and verify/decrypt a value written by `writeEncryptedLocal`.
 * Returns the plaintext JSON string, or null if the key is absent, the
 * signature fails (tampered), or decryption fails (wrong key / corrupted).
 */
export async function readDecryptedLocal(key: string): Promise<string | null> {
  const raw = localStorage.getItem(key);
  if (!raw) return null;

  // ── v2 (Argon2id / L5) ──────────────────────────────────────────────────
  if (raw.startsWith(V2_PREFIX)) {
    try {
      const parts = raw.split('.');
      if (parts.length < 3) return null;
      const header = fromB64u(parts[1]);
      if (header[0] !== V2_VERSION) return null;

      // Verify signature if present
      const sk = keyStore.getSigningKey(2);
      if (sk && parts.length >= 4) {
        const sigInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}.${parts[2]}`);
        const sig = fromB64u(parts[3]);
        if (!await crypto.subtle.verify('HMAC', sk, sig, sigInput)) return null;
      }

      const ck = keyStore.getLocalKey(2);
      if (!ck) return null;

      const ivCt = fromB64u(parts[2]);
      const iv = ivCt.slice(0, 12);
      const ct = ivCt.slice(12);

      const aad = new Uint8Array(header.length + key.length);
      aad.set(header);
      aad.set(new TextEncoder().encode(key), header.length);

      return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, ck, ct));
    } catch { return null; }
  }

  // ── Legacy JSON format: {"enc":1,"iv":"...","ct":"..."} ───────────────────
  if (raw.startsWith('{')) {
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      if (parsed['enc'] !== 1) return null; // Disallow plaintext legacy fallback
      const ck = keyStore.getLocalKey(1);
      if (!ck) return null;
      const iv = Uint8Array.from(atob(parsed['iv'] as string), c => c.charCodeAt(0));
      const ct = Uint8Array.from(atob(parsed['ct'] as string), c => c.charCodeAt(0));
      return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, ck, ct));
    } catch { return null; }
  }

  // ── Compact JWT-like format: header.payload[.sig] ────────────────────────
  try {
    const parts = raw.split('.');
    if (parts.length < 2) return null;

    // Verify HMAC signature when signing key and signature are both present.
    const sk = keyStore.getSigningKey(1);
    if (sk && parts.length >= 3) {
      const sigInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
      const sig = fromB64u(parts[2]);
      const valid = await crypto.subtle.verify('HMAC', sk, sig, sigInput);
      if (!valid) return null; // tampered token - hard reject
    }

    const ck = keyStore.getLocalKey(1);
    if (!ck) return null;

    const ivCt = fromB64u(parts[1]);
    const iv = ivCt.slice(0, 12);
    const ct = ivCt.slice(12);
    return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, ck, ct));
  } catch { return null; }
}
