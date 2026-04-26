/**
 * SecureKeyStore — holds the daemon session token and local config encryption key
 * in memory only. Both are derived/received at login and cleared on tab close.
 *
 * Architecture §10: "Keys NEVER enter React state, localStorage, sessionStorage,
 * or IndexedDB. VMK lives only in the daemon; browser holds only a short-lived
 * session token."
 */
export class SecureKeyStore {
  #token: Uint8Array | null = null;
  #localKey: CryptoKey | null = null;

  store(token: string): void {
    this.#token = new TextEncoder().encode(token);
  }

  get(): string | null {
    if (!this.#token) return null;
    return new TextDecoder().decode(this.#token);
  }

  /** Store the per-session AES-GCM-256 key for encrypting local config (MFA, notifications, SMTP). */
  storeLocalKey(key: CryptoKey): void {
    this.#localKey = key;
  }

  /** Retrieve the local config encryption key; null if not yet derived (before login). */
  getLocalKey(): CryptoKey | null {
    return this.#localKey;
  }

  clear(): void {
    if (this.#token) {
      crypto.getRandomValues(this.#token);
      this.#token = null;
    }
    this.#localKey = null;
  }

  get hasToken(): boolean {
    return this.#token !== null;
  }
}

/** Singleton keystore — one per browser tab. */
export const keyStore = new SecureKeyStore();

// Clear both the session token and local key when the tab is discarded or hidden.
if (typeof window !== 'undefined') {
  window.addEventListener('pagehide', () => keyStore.clear());
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') keyStore.clear();
  });
}

/**
 * Derive an AES-GCM-256 local config encryption key from the master password
 * and a per-installation salt. The salt is non-sensitive random bytes stored in
 * localStorage as `_lk_salt`; it ensures the derived key is unique per device.
 *
 * This key protects local config (MFA secrets, notifications, SMTP credentials)
 * that cannot live in the daemon. The raw password is never persisted.
 */
export async function deriveLocalKey(password: string, saltHex: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const passwordBytes = enc.encode(password);
  const saltBytes = /^[0-9a-f]{32}$/i.test(saltHex)
    ? Uint8Array.from(saltHex.match(/../g)!.map(h => parseInt(h, 16)))
    : enc.encode(saltHex);

  const baseKey = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: 310_000 },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Return the per-installation local key salt from localStorage, generating and
 * persisting a fresh one if none exists. The salt value is non-sensitive (public
 * PBKDF2 parameter — random bytes, not a secret).
 */
export function getOrCreateLocalKeySalt(): string {
  const existing = localStorage.getItem('_lk_salt');
  if (existing) return existing;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  localStorage.setItem('_lk_salt', salt);
  return salt;
}
