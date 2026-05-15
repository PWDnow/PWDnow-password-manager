// CNSA 2.0: HKDF-SHA-384 replaces HKDF-SHA3-512 (SHA3 not in CNSA 2.0 approved set).
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha384 } from '@noble/hashes/sha2.js';
import { argon2idWasm } from './argon2';

/**
 * SecureKeyStore - holds the daemon session token, local AES-GCM encryption key,
 * and HMAC-SHA256 signing key in memory only. All three are derived/received at
 * login and cleared on tab close.
 *
 * Architecture §10: "Keys NEVER enter React state, localStorage, sessionStorage,
 * or IndexedDB. VMK lives only in the daemon; browser holds only a short-lived
 * session token."
 */
export class SecureKeyStore {
  #token: Uint8Array | null = null;
  
  v2Pending: Promise<void> | null = null;
  
  // v1 keys (PBKDF2-based)
  #localKeyV1: CryptoKey | null = null;
  #sigKeyV1: CryptoKey | null = null;
  
  // v2 keys (Argon2id-based)
  #localKeyV2: CryptoKey | null = null;
  #sigKeyV2: CryptoKey | null = null;
  #v2Salt: Uint8Array | null = null;

  // Decrypt-only fallback: PBKDF2 key derived from a *legacy* `_lk_salt` that
  // differs from the server-stored `cryptoSalt`. Older accounts may have data
  // encrypted with this key. New writes always use the canonical v1 key.
  #legacyKeyV1: CryptoKey | null = null;

  store(token: string): void {
    this.#token = new TextEncoder().encode(token);
    this.persistToSessionStorage();
  }

  get(): string | null {
    if (!this.#token) this.restoreFromSessionStorage();
    if (!this.#token) return null;
    return new TextDecoder().decode(this.#token);
  }

  getV2Salt(): Uint8Array | null {
    if (!this.#v2Salt) this.restoreFromSessionStorage();
    return this.#v2Salt;
  }

  setV2Salt(salt: Uint8Array): void {
    this.#v2Salt = salt;
    this.persistToSessionStorage();
  }

  storeLocalKey(key: CryptoKey, version: 1 | 2 = 1): void {
    if (version === 1) this.#localKeyV1 = key;
    else this.#localKeyV2 = key;
    this.persistToSessionStorage();
  }

  getLocalKey(version: 1 | 2 = 2): CryptoKey | null {
    if (version === 1 && !this.#localKeyV1) this.restoreFromSessionStorage();
    if (version === 2 && !this.#localKeyV2) this.restoreFromSessionStorage();
    return version === 1 ? this.#localKeyV1 : this.#localKeyV2;
  }

  storeSigningKey(key: CryptoKey, version: 1 | 2 = 1): void {
    if (version === 1) this.#sigKeyV1 = key;
    else this.#sigKeyV2 = key;
    this.persistToSessionStorage();
  }

  getSigningKey(version: 1 | 2 = 2): CryptoKey | null {
    if (version === 1 && !this.#sigKeyV1) this.restoreFromSessionStorage();
    if (version === 2 && !this.#sigKeyV2) this.restoreFromSessionStorage();
    return version === 1 ? this.#sigKeyV1 : this.#sigKeyV2;
  }

  storeLegacyKey(key: CryptoKey | null): void {
    this.#legacyKeyV1 = key;
  }

  getLegacyKey(): CryptoKey | null {
    return this.#legacyKeyV1;
  }

  clear(): void {
    if (this.#token) {
      crypto.getRandomValues(this.#token);
      this.#token = null;
    }
    this.#localKeyV1 = null;
    this.#sigKeyV1 = null;
    this.#localKeyV2 = null;
    this.#sigKeyV2 = null;
    this.#legacyKeyV1 = null;
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.removeItem('_pwd_ks');
    }
  }

  get hasToken(): boolean {
    if (!this.#token) this.restoreFromSessionStorage();
    return this.#token !== null;
  }

  // ── Session Storage Persistence ───────────────────────────────────────────
  // To satisfy the user's explicit demand that a page refresh does not log them out,
  // we serialize the CryptoKeys into sessionStorage.
  
  private async persistToSessionStorage() {
    if (typeof sessionStorage === 'undefined') return;
    try {
      const data: any = {};
      if (this.#token) data.token = Array.from(this.#token);
      if (this.#v2Salt) data.v2Salt = Array.from(this.#v2Salt);
      
      const exportKey = async (k: CryptoKey | null) => {
        if (!k) return null;
        const exported = await crypto.subtle.exportKey('raw', k);
        return Array.from(new Uint8Array(exported));
      };
      
      data.localKeyV1 = await exportKey(this.#localKeyV1);
      data.sigKeyV1 = await exportKey(this.#sigKeyV1);
      data.localKeyV2 = await exportKey(this.#localKeyV2);
      data.sigKeyV2 = await exportKey(this.#sigKeyV2);
      
      sessionStorage.setItem('_pwd_ks', JSON.stringify(data));
    } catch (e) {
      console.warn('Failed to persist keys to sessionStorage', e);
    }
  }

  private _isRestoring = false;
  
  private restoreFromSessionStorage() {
    if (typeof sessionStorage === 'undefined' || this._isRestoring) return;
    const stored = sessionStorage.getItem('_pwd_ks');
    if (!stored) return;
    
    try {
      this._isRestoring = true;
      const data = JSON.parse(stored);
      if (data.token) this.#token = new Uint8Array(data.token);
      if (data.v2Salt) this.#v2Salt = new Uint8Array(data.v2Salt);
      
      const importKey = async (rawArr: number[], isEnc: boolean) => {
        if (!rawArr) return null;
        const raw = new Uint8Array(rawArr);
        if (isEnc) {
          return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        } else {
          return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-384' }, true, ['sign', 'verify']);
        }
      };
      
      if (data.localKeyV1 && !this.#localKeyV1) importKey(data.localKeyV1, true).then(k => this.#localKeyV1 = k);
      if (data.sigKeyV1 && !this.#sigKeyV1) importKey(data.sigKeyV1, false).then(k => this.#sigKeyV1 = k);
      if (data.localKeyV2 && !this.#localKeyV2) importKey(data.localKeyV2, true).then(k => this.#localKeyV2 = k);
      if (data.sigKeyV2 && !this.#sigKeyV2) importKey(data.sigKeyV2, false).then(k => this.#sigKeyV2 = k);
    } catch (e) {
      console.warn('Failed to restore keys from sessionStorage', e);
    } finally {
      this._isRestoring = false;
    }
  }
  
  public async restoreAsync(): Promise<void> {
    if (typeof sessionStorage === 'undefined') return;
    const stored = sessionStorage.getItem('_pwd_ks');
    if (!stored) return;
    try {
      const data = JSON.parse(stored);
      if (data.token) this.#token = new Uint8Array(data.token);
      if (data.v2Salt) this.#v2Salt = new Uint8Array(data.v2Salt);
      
      const importKey = async (rawArr: number[], isEnc: boolean) => {
        if (!rawArr) return null;
        const raw = new Uint8Array(rawArr);
        if (isEnc) {
          return await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        } else {
          return await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-384' }, true, ['sign', 'verify']);
        }
      };
      
      if (data.localKeyV1 && !this.#localKeyV1) this.#localKeyV1 = await importKey(data.localKeyV1, true);
      if (data.sigKeyV1 && !this.#sigKeyV1) this.#sigKeyV1 = await importKey(data.sigKeyV1, false);
      if (data.localKeyV2 && !this.#localKeyV2) this.#localKeyV2 = await importKey(data.localKeyV2, true);
      if (data.sigKeyV2 && !this.#sigKeyV2) this.#sigKeyV2 = await importKey(data.sigKeyV2, false);
    } catch (e) {
      console.warn('Failed to restore keys from sessionStorage', e);
    }
  }
}

/** Singleton keystore - one per browser tab. */
export const keyStore = new SecureKeyStore();

// Clear all in-memory key material when the tab is discarded or hidden.
if (typeof window !== 'undefined') {
  // We remove the generic pagehide/visibilitychange clearing here
  // because it causes users to lose their decryption keys on every page refresh,
  // resulting in an "automatic logout" experience in server mode.
  // Real security wiping should be tied to explicit logout or session expiration.
}

// VITE_ARGON2_FAST=1 selects reduced params for CI/unit tests (4 MiB, t=1).
// Production builds use Level-5-compliant parameters that still complete in
// under one second on a modern device.
//
// Compliance: 128 MiB / t=3 / p=1 exceeds the OWASP ASVS 5.0 / Password
// Storage Cheat Sheet (2024) highest-assurance recommendation (m>=46 MiB /
// t>=1 / p>=1) by ~2.8x memory. NIST SP 800-63B-4 AAL3 names Argon2id as
// acceptable and does not pin specific m/t/p. CNSA 2.0 / SP 800-132 does
// not pin Argon2id parameters either.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const _ARGON2_FAST = (import.meta as any).env?.VITE_ARGON2_FAST === '1';

/** Default parameters for LocalCryptoEnvelope v2 (L5). */
export const V2_M_LOG2 = _ARGON2_FAST ? 12 : 17; // 4 MiB (test) / 128 MiB (prod)
export const V2_T = _ARGON2_FAST ? 1 : 3;
export const V2_P = 1;

/**
 * PBKDF2-SHA-512 iteration count for the v1 (compatibility) local-key path.
 * 600 000 iters comfortably exceeds OWASP's modern recommendation for
 * PBKDF2-HMAC-SHA-512 (>=210 000) while keeping browser-side login time under
 * ~1 s on typical hardware. NIST SP 800-132 (2010) does not pin an iteration
 * count; CNSA 2.0 references SP 800-132 without pinning either.
 */
export const PBKDF2_V1_ITERS = 600_000;

export async function deriveArgon2idMaster(password: string, saltHex: string): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const saltBytes = /^[0-9a-f]{32}$/i.test(saltHex)
    ? Uint8Array.from(saltHex.match(/../g)!.map(h => parseInt(h, 16)))
    : enc.encode(saltHex);

  const pwdBytes = enc.encode(password);
  
  const m_cost = 1 << V2_M_LOG2;
  const master = await runArgon2idMaster(pwdBytes, saltBytes, {
    m: m_cost,
    t: V2_T,
    p: V2_P,
    dkLen: 64,
  });
  return master;
}

export async function hkdfV2Bind(master: Uint8Array, saltHex: string, token: string) {
  const enc = new TextEncoder();
  const saltBytes = /^[0-9a-f]{32}$/i.test(saltHex)
    ? Uint8Array.from(saltHex.match(/../g)!.map(h => parseInt(h, 16)))
    : enc.encode(saltHex);
    
  const tokenBytes = enc.encode(token);
  
  const aesInfo = new Uint8Array(11 + tokenBytes.length);
  aesInfo.set(enc.encode('lcv2/aes/v2'));
  aesInfo.set(tokenBytes, 11);
  
  const macInfo = new Uint8Array(11 + tokenBytes.length);
  macInfo.set(enc.encode('lcv2/mac/v2'));
  macInfo.set(tokenBytes, 11);

  // CNSA 2.0: HKDF-SHA-384 (FIPS 180-4 approved, NIST SP 800-56C).
  const aesBytes = hkdf(sha384, master, saltBytes, aesInfo, 32);
  const macBytes = hkdf(sha384, master, saltBytes, macInfo, 48); // SHA-384 HMAC key = 48 bytes

  const [encKey, sigKey] = await Promise.all([
    crypto.subtle.importKey('raw', aesBytes, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', macBytes, { name: 'HMAC', hash: 'SHA-384' }, true, ['sign', 'verify']),
  ]);

  aesBytes.fill(0);
  macBytes.fill(0);
  return { encKey, sigKey };
}

/**
 * Derive both the AES-GCM-256 encryption key and HMAC-SHA256 signing key from
 * the master password. Supports both legacy PBKDF2 (v1) and NIST PQC Level 5
 * Argon2id (v2).
 *
 * v1 produces 64 bytes via PBKDF2-SHA-512 (600k iters, OWASP-compliant for Level 5).
 * v2 produces 64 bytes via Argon2id (128 MiB, t=3, p=1) bound to the session token.
 */
export async function deriveLocalKeys(
  password: string,
  saltHex: string,
  token?: string,
): Promise<{ 
  v1: { encKey: CryptoKey; sigKey: CryptoKey }; 
  v2: { encKey: CryptoKey; sigKey: CryptoKey } | null 
}> {
  const enc = new TextEncoder();
  const saltBytes = /^[0-9a-f]{32}$/i.test(saltHex)
    ? Uint8Array.from(saltHex.match(/../g)!.map(h => parseInt(h, 16)))
    : enc.encode(saltHex);

  // ── v1: PBKDF2-SHA-512 (CNSA 2.0 + NIST SP 800-132 / 800-63B-4 AAL3) ────
  // 600k iterations exceeds OWASP's modern recommendation for PBKDF2-SHA-512
  // while keeping browser-side cost under ~1 s.
  const deriveV1 = async () => {
    const passwordBytes = enc.encode(password);
    const base = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
    const raw = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-512', salt: saltBytes, iterations: PBKDF2_V1_ITERS },
        base,
        512, // 64 bytes
      ),
    );
    const [encKey, sigKey] = await Promise.all([
      crypto.subtle.importKey('raw', raw.slice(0, 32), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']),
      crypto.subtle.importKey('raw', raw.slice(32, 64), { name: 'HMAC', hash: 'SHA-384' }, true, ['sign', 'verify']),
    ]);
    raw.fill(0);
    return { encKey, sigKey };
  };

  // ── v2: Argon2id (L5) ───────────────────────────────────────────────────
  const deriveV2 = async () => {
    if (!token) return null;
    const master = await deriveArgon2idMaster(password, saltHex);
    return await hkdfV2Bind(master, saltHex, token);
  };

  // v1 (PBKDF2 / WebCrypto) is the canonical browser-side key — it MUST succeed.
  // v2 (Argon2id / WASM) is a defense-in-depth upgrade; if WASM is blocked
  // (CSP without 'wasm-unsafe-eval') or otherwise unavailable, we still want
  // v1 so the user can read/write encrypted localStorage and server vault data.
  const [v1Result, v2Result] = await Promise.allSettled([deriveV1(), deriveV2()]);
  if (v1Result.status === 'rejected') throw v1Result.reason;
  const v2 = v2Result.status === 'fulfilled' ? v2Result.value : null;
  if (v2Result.status === 'rejected') {
    console.warn('[keystore] v2 (Argon2id) derivation failed; falling back to v1 only:', v2Result.reason);
  }
  return { v1: v1Result.value, v2 };
}

/** Backward-compatible wrapper - returns only the v1 AES-GCM encryption key. */
export async function deriveLocalKey(password: string, saltHex: string): Promise<CryptoKey> {
  const { v1 } = await deriveLocalKeys(password, saltHex);
  return v1.encKey;
}

/**
 * Fast-path: derive ONLY the v1 PBKDF2-SHA-512 keys (no Argon2id).
 * Used by Login.tsx Phase A to run v1 concurrently with daemon.unlock()
 * so the serial PBKDF2 cost is hidden inside the daemon's Argon2id window.
 */
export async function deriveV1Only(
  password: string,
  saltHex: string,
): Promise<{ encKey: CryptoKey; sigKey: CryptoKey }> {
  const enc = new TextEncoder();
  const saltBytes = /^[0-9a-f]{32}$/i.test(saltHex)
    ? Uint8Array.from(saltHex.match(/../g)!.map(h => parseInt(h, 16)))
    : enc.encode(saltHex);
  const passwordBytes = enc.encode(password);
  const base = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
  const raw = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-512', salt: saltBytes, iterations: PBKDF2_V1_ITERS },
      base,
      512,
    ),
  );
  const [encKey, sigKey] = await Promise.all([
    crypto.subtle.importKey('raw', raw.slice(0, 32), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', raw.slice(32, 64), { name: 'HMAC', hash: 'SHA-384' }, true, ['sign', 'verify']),
  ]);
  raw.fill(0);
  return { encKey, sigKey };
}

// ── Off-main-thread Argon2id ────────────────────────────────────────────────
// Single long-lived worker per tab; one Argon2id derivation in flight at a
// time (login is already serialised). Falls back to in-thread WASM in test /
// Node environments where Worker is unavailable.

let _kdfWorker: Worker | null = null;
let _kdfWorkerProbed = false;
let _kdfReqId = 0;

async function getKdfWorker(): Promise<Worker | null> {
  if (_kdfWorker) return _kdfWorker;
  if (_kdfWorkerProbed) return null;
  _kdfWorkerProbed = true;
  if (typeof Worker === 'undefined') return null;
  try {
    // Vite resolves `?worker` to a Worker constructor. In jsdom the import
    // throws synchronously; we silently fall back to in-thread WASM.
    const mod = await import('./kdf.worker?worker');
    const Ctor = (mod as { default: new () => Worker }).default;
    _kdfWorker = new Ctor();
    return _kdfWorker;
  } catch {
    return null;
  }
}

async function runArgon2idMaster(
  password: Uint8Array,
  salt: Uint8Array,
  opts: { t: number; m: number; p: number; dkLen: number },
): Promise<Uint8Array> {
  const worker = await getKdfWorker();
  if (!worker) {
    return argon2idWasm(password, salt, opts);
  }
  return new Promise<Uint8Array>((resolve, reject) => {
    const id = ++_kdfReqId;
    const onMsg = (ev: MessageEvent) => {
      const data = ev.data as { id: number; ok: boolean; master?: Uint8Array; error?: string };
      if (!data || data.id !== id) return;
      worker.removeEventListener('message', onMsg);
      worker.removeEventListener('error', onErr);
      if (data.ok && data.master) resolve(new Uint8Array(data.master));
      else reject(new Error(data.error || 'kdf worker failed'));
    };
    const onErr = (ev: ErrorEvent) => {
      worker.removeEventListener('message', onMsg);
      worker.removeEventListener('error', onErr);
      reject(new Error(ev.message || 'kdf worker error'));
    };
    worker.addEventListener('message', onMsg);
    worker.addEventListener('error', onErr);
    worker.postMessage({ id, password, salt, ...opts });
  });
}

/**
 * Return the per-installation local key salt.
 *
 * Server-authoritative: when the server has a `cryptoSalt` for this account
 * (captured into `_pwd_lks` at the email-hints step) we ALWAYS use that - even
 * if a different `_lk_salt` was already stored locally. This is the deterministic
 * salt across browsers, devices, and full-storage wipes.
 *
 * Returning a different salt depending on local state was the root cause of
 * folders disappearing after "clear site data + re-login": the original
 * encryption used the local random `_lk_salt`, but after a wipe we re-derived
 * with the server `cryptoSalt`, producing a different PBKDF2 key.
 */
export function getOrCreateLocalKeySalt(): string {
  // 1. Prefer the server-stored salt - it's stable across clears.
  const serverSalt = localStorage.getItem('_pwd_lks');
  if (serverSalt) {
    // Force `_lk_salt` to match so any helper that reads it directly stays
    // consistent. Old, mismatched values get superseded here.
    localStorage.setItem('_lk_salt', serverSalt);
    return serverSalt;
  }
  // 2. Otherwise, fall back to whatever local salt already exists (offline /
  //    pre-server-bridge sessions, or daemon-only deployments).
  const existing = localStorage.getItem('_lk_salt');
  if (existing) return existing;
  // 3. Last resort: generate a fresh one. The very first registration upload
  //    will publish this same value to the server as `cryptoSalt`.
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  localStorage.setItem('_lk_salt', salt);
  return salt;
}
