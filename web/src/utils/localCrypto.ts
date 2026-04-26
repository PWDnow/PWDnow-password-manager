import { keyStore } from '../crypto/keystore';

function bytesToB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

/**
 * Write `value` (JSON string) to localStorage under `key`.
 * When the demo encryption key is available, AES-GCM-256 encrypts before write.
 * When no key is available, an existing encrypted blob is preserved (no overwrite)
 * to prevent data loss — plain JSON is written only if no encrypted data exists.
 */
export async function writeEncryptedLocal(key: string, value: string): Promise<void> {
  const ck = keyStore.getLocalKey();
  if (ck) {
    try {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const pt = new TextEncoder().encode(value);
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, ck, pt));
      localStorage.setItem(key, JSON.stringify({ enc: 1, iv: bytesToB64(iv), ct: bytesToB64(ct) }));
      return;
    } catch { /* fall through */ }
  }
  try {
    const existing = localStorage.getItem(key);
    if (existing && (JSON.parse(existing) as Record<string, unknown>).enc === 1) return;
  } catch { /* not JSON — safe to overwrite */ }
  try { localStorage.setItem(key, value); } catch { /* quota / private mode */ }
}

/**
 * Read and decrypt a value written by `writeEncryptedLocal`.
 * Returns the plaintext JSON string, or null if the key is absent or decryption fails.
 */
export async function readDecryptedLocal(key: string): Promise<string | null> {
  const raw = localStorage.getItem(key);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed.enc === 1) {
      const ck = keyStore.getLocalKey();
      if (!ck) return null;
      const iv = b64ToBytes(parsed.iv);
      const ct = b64ToBytes(parsed.ct);
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, ck, ct);
      return new TextDecoder().decode(pt);
    }
    return raw;
  } catch {
    return null;
  }
}
