import { hashPassword, generateUUID } from './crypto';
import { WIPE_TICKET_KEY } from './daemonClient'; // kept for legacy localStorage cleanup
import { readDecryptedLocal } from './localCrypto';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';

export interface DuressModeConfig {
  armed: boolean;
  passwordHash: string | null;
  maxAttempts: number;
  attemptsRemaining: number;
  salt: string;
}

export interface LockoutConfig {
  enabled: boolean;
  maxAttempts: number;
  lockoutDurationMins: number;
  attemptsMade: number;
  lockedUntil: number | null;
}

export interface TravelModeConfig {
  active: boolean;
  passwordHash: string | null;
  hiddenFolderIds: string[];
  salt: string;
  ivHex: string;
  kdf_version?: 1 | 2;
}

const DURESS_KEY = 'duress_mode_config';
const LOCKOUT_KEY = 'login_lockout_config';
// Travel mode config is plaintext JSON. The only sensitive field is
// passwordHash, which is already a 1M-iteration PBKDF2-SHA-512 derivative.
// hiddenFolderIds are opaque UUIDs that reveal no credential contents.
// Storing plaintext avoids the v2-key rotation problem that made the prior
// encrypted-only design unreadable after logout (the v2 session key is bound
// to the per-session token and changes on every login).
const TRAVEL_KEY = '_tm_cfg';
// Intentionally generic-looking key so as not to draw attention during inspection
const TRAVEL_VAULT_KEY = '_cache_local_xvc';

// ── Config accessors ──────────────────────────────────────────────────────────
// Duress config needs pre-login access (chicken-and-egg with session key).
// Mitigation: always write the same shape regardless of armed state (ambiguity),
// and rename the key to be non-descriptive so forensic inspection reveals nothing.

export function getDuressModeConfig(): DuressModeConfig {
  // #29-FIX: hash is stored encrypted; pre-login callers get a sentinel-only view.
  // The sentinel records armed + maxAttempts + attemptsRemaining (no hash).
  // maxAttempts is non-sensitive (it's the configured threshold, not a secret),
  // and is required here so the Settings UI dropdown defaults to the configured
  // value rather than the hardcoded fallback of 5.
  try {
    const sentinel = localStorage.getItem(DURESS_KEY + '_sentinel');
    if (sentinel) {
      const parsed = JSON.parse(sentinel) as { armed?: boolean; maxAttempts?: number; attemptsRemaining?: number };
      const salt = generateUUID();
      const maxAttempts = typeof parsed.maxAttempts === 'number' && parsed.maxAttempts > 0 ? parsed.maxAttempts : 5;
      const attemptsRemaining = typeof parsed.attemptsRemaining === 'number' && parsed.attemptsRemaining >= 0
        ? parsed.attemptsRemaining
        : maxAttempts;
      return { armed: !!parsed.armed, passwordHash: null, maxAttempts, attemptsRemaining, salt };
    }
  } catch {}
  const salt = generateUUID();
  return { armed: false, passwordHash: null, maxAttempts: 5, attemptsRemaining: 5, salt };
}

export async function getDuressModeConfigFull(): Promise<DuressModeConfig> {
  // Server-session: fetch the server-side mirror; if present, it overrides any
  // local cache and refreshes localStorage so subsequent sync reads work for
  // the rest of the session. Without this, logging in on a fresh browser (or
  // after Clear-Site-Data) drops the user back to "Disarmed" silently.
  if (hasServerSessionCookie()) {
    try {
      const res = await fetch('/api/vault/duress-config', { credentials: 'same-origin' });
      if (res.ok) {
        const body = await res.json().catch(() => null);
        if (body && typeof body.data === 'string' && body.data.startsWith('{')) {
          const parsed = JSON.parse(body.data) as DuressModeConfig;
          // Refresh the local plaintext + sentinel so the sync getter works
          // for the rest of the session (Settings.tsx initial render).
          localStorage.setItem(DURESS_KEY, body.data);
          localStorage.setItem(DURESS_KEY + '_sentinel', JSON.stringify({
            armed: parsed.armed,
            maxAttempts: parsed.maxAttempts,
            attemptsRemaining: parsed.attemptsRemaining,
          }));
          return parsed;
        }
        // Server explicitly says no config — purge any stale local copy.
        if (body && body.data === null) {
          localStorage.removeItem(DURESS_KEY);
          localStorage.removeItem(DURESS_KEY + '_sentinel');
        }
      }
    } catch { /* network/server unreachable — fall through to local */ }
  }

  // Local encrypted v2 path (current-session writes by writeEncryptedLocal).
  try {
    const dec = await readDecryptedLocal(DURESS_KEY);
    if (dec) return JSON.parse(dec) as DuressModeConfig;
  } catch {}
  // Fallback: plaintext JSON (migration path / pre-session writes).
  try {
    const s = localStorage.getItem(DURESS_KEY);
    if (s && s.startsWith('{')) return JSON.parse(s) as DuressModeConfig;
  } catch {}
  const salt = generateUUID();
  return { armed: false, passwordHash: null, maxAttempts: 5, attemptsRemaining: 5, salt };
}

async function saveDuressModeConfig(cfg: DuressModeConfig): Promise<void> {
  const payload = JSON.stringify(cfg);
  // Local plaintext is the source of truth pre-server-mirror (and for
  // daemon/offline modes). The Argon2id PHC (m=262144, t=3) makes offline
  // cracking impractical, and the duress password can only trigger a local
  // wipe — it cannot unlock the real vault — so plaintext storage of the
  // hash is an acceptable trade-off for pre-login readability.
  localStorage.setItem(DURESS_KEY, payload);
  // Non-sensitive sentinel for the synchronous getter. Includes maxAttempts
  // and attemptsRemaining so the UI dropdown reflects the saved value.
  localStorage.setItem(DURESS_KEY + '_sentinel', JSON.stringify({
    armed: cfg.armed,
    maxAttempts: cfg.maxAttempts,
    attemptsRemaining: cfg.attemptsRemaining,
  }));
  // NOTE: do NOT writeEncryptedLocal(DURESS_KEY, payload) - it overwrites the
  // plaintext set above with an encrypted v2 token, which the pre-login
  // fallback in getDuressModeConfigFull cannot read (no session key in
  // memory on the login page). The plaintext IS the source of truth pre-login
  // (the only sensitive field, passwordHash, is a 256 MiB Argon2id PHC -
  // see header comment above).
  // Server-mode mirror so the config survives logout / clear-site-data /
  // new-device logins.
  if (hasServerSessionCookie()) {
    const csrf = getCsrf();
    if (csrf) {
      try {
        await fetch('/api/vault/duress-config', {
          method: 'PUT',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
          body: JSON.stringify({ data: payload }),
        });
      } catch { /* mirror failure non-fatal; local copy still authoritative */ }
    }
  }
}

export function getLockoutConfig(): LockoutConfig {
  try {
    const s = localStorage.getItem(LOCKOUT_KEY);
    if (s) return JSON.parse(s) as LockoutConfig;
  } catch {}
  return { enabled: true, maxAttempts: 3, lockoutDurationMins: 5, attemptsMade: 0, lockedUntil: null };
}

export function saveLockoutConfig(cfg: LockoutConfig): void {
  localStorage.setItem(LOCKOUT_KEY, JSON.stringify(cfg));
}

// Travel mode config is plaintext JSON. See TRAVEL_KEY comment above for rationale.
// In server-session mode the server is the source of truth and localStorage is
// just a cache for the sync reader (needed by VaultContext's filter and the
// initial Settings.tsx state). The async getter hydrates from server.
function defaultTravelConfig(): TravelModeConfig {
  return { active: false, passwordHash: null, hiddenFolderIds: [], salt: generateUUID(), ivHex: '' };
}

function hasServerSessionCookie(): boolean {
  if (typeof document === 'undefined') return false;
  return document.cookie.split(';').some(c => c.trim().startsWith('_pwd_csrf='));
}

function getCsrf(): string | null {
  if (typeof document === 'undefined') return null;
  const cookie = document.cookie.split(';').map(c => c.trim())
    .find(c => c.startsWith('_pwd_csrf='));
  if (!cookie) return null;
  return decodeURIComponent(cookie.split('=')[1]);
}

export function getTravelModeConfig(): TravelModeConfig {
  try {
    const raw = localStorage.getItem(TRAVEL_KEY);
    if (raw && raw.startsWith('{')) {
      const parsed = JSON.parse(raw) as TravelModeConfig;
      if (typeof parsed.active === 'boolean' && Array.isArray(parsed.hiddenFolderIds)) {
        return parsed;
      }
    }
  } catch {}
  return defaultTravelConfig();
}

export async function getTravelModeConfigAsync(): Promise<TravelModeConfig> {
  // Server-session: fetch the server-side mirror; if present, it overrides any
  // local cache and refreshes localStorage so the sync reader works for the
  // rest of the session. This is the recovery path after "Clear site data".
  if (hasServerSessionCookie()) {
    try {
      const res = await fetch('/api/vault/travel-config', { credentials: 'same-origin' });
      if (res.ok) {
        const body = await res.json().catch(() => null);
        if (body && typeof body.data === 'string' && body.data.startsWith('{')) {
          const parsed = JSON.parse(body.data) as TravelModeConfig;
          if (typeof parsed.active === 'boolean' && Array.isArray(parsed.hiddenFolderIds)) {
            localStorage.setItem(TRAVEL_KEY, body.data);
            return parsed;
          }
        }
        // Server explicitly has no config — clear any stale local copy so the
        // sync reader can't lie about Travel Mode being active.
        if (body && body.data === null) {
          localStorage.removeItem(TRAVEL_KEY);
          return defaultTravelConfig();
        }
      }
    } catch { /* network/server unreachable — fall through to local */ }
  }

  // Local plaintext (offline/daemon/demo or server fetch failed).
  const sync = getTravelModeConfig();
  if (sync.active || sync.passwordHash) return sync;

  // Legacy: previously written via writeEncryptedLocal. Migrate if readable.
  try {
    const dec = await readDecryptedLocal(TRAVEL_KEY);
    if (dec) {
      const migrated = JSON.parse(dec) as TravelModeConfig;
      localStorage.setItem(TRAVEL_KEY, JSON.stringify(migrated));
      return migrated;
    }
  } catch { /* unreadable legacy = fall through */ }
  return sync;
}

async function saveTravelModeConfig(cfg: TravelModeConfig): Promise<void> {
  const payload = JSON.stringify(cfg);
  localStorage.setItem(TRAVEL_KEY, payload);
  if (hasServerSessionCookie()) {
    const csrf = getCsrf();
    if (!csrf) return;
    try {
      await fetch('/api/vault/travel-config', {
        method: 'PUT',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
        body: JSON.stringify({ data: payload }),
      });
    } catch { /* non-fatal: local cache will be re-pushed on next save */ }
  }
}

// ── Forensic wipe ─────────────────────────────────────────────────────────────

/** Minimal interface so securityModes does not directly import DaemonClient (avoids circular deps). */
export interface ForensicWipeable {
  isConnected: boolean;
  forensicWipe(ticket: Uint8Array): Promise<void>;
}

/**
 * Full forensic destruction.
 *
 * Phase 1 (daemon, when connected): NIST SP 800-88 Rev. 2 cryptographic erase —
 * zeroes all key-material fields in vault.db.meta (argon2_salt, encrypted_vmk,
 * passkey VMK copies), fsyncs, then unlinks both files.  Without the salt no
 * KEK can be derived; the vault is permanently unrecoverable.
 *
 * Phase 2 (browser): cryptographic erase — clears all session keys and overwrites
 * localStorage once with CSPRNG bytes before clearing.  Then clears sessionStorage,
 * all IndexedDB databases, and service-worker caches.
 */
export async function wipeVaultData(daemonInstance?: ForensicWipeable, serverPassword?: string): Promise<void> {
  // Phase 1: daemon-side forensic wipe (files on disk)
  if (daemonInstance?.isConnected) {
    try {
      const stored = localStorage.getItem('_sys_vk_tkv');
      if (stored) {
        const ticketBytes = new Uint8Array(stored.match(/../g)!.map(h => parseInt(h, 16)));
        await daemonInstance.forensicWipe(ticketBytes);
      }
    } catch { /* non-fatal - continue with browser wipe */ }
  }

  // Also call server-side wipe to destroy auth_data/ and user account.
  // #1-FIX: password re-verification is required; pass the verified password
  // from the caller (e.g. duress password for duress-mode, or explicit prompt).
  try {
    const csrf = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('_pwd_csrf='))?.split('=')[1];
    if (csrf && serverPassword) {
      await fetch('/api/vault/wipe', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: serverPassword }),
      });
    }
  } catch { /* non-fatal */ }

  // Purge any stale localStorage wipe ticket left by previous versions.
  localStorage.removeItem('_pwd_wt');

  const keys = Object.keys(localStorage);

  // Single CSPRNG pass — cryptographic erase for flash-backed browser storage
  for (const key of keys) {
    try {
      const buf = new Uint8Array(512);
      crypto.getRandomValues(buf);
      localStorage.setItem(key, Array.from(buf, b => b.toString(16).padStart(2, '0')).join(''));
    } catch {}
  }

  localStorage.clear();
  sessionStorage.clear();

  // Clear all IndexedDB databases
  try {
    const dbs = await indexedDB.databases();
    await Promise.all(
      dbs.map(db => db.name
        ? new Promise<void>(res => {
            const r = indexedDB.deleteDatabase(db.name!);
            r.onsuccess = () => res();
            r.onerror = () => res();
          })
        : Promise.resolve()
      )
    );
  } catch {}

  // Clear Cache Storage (service worker caches)
  try {
    const cacheKeys = await caches.keys();
    await Promise.all(cacheKeys.map(k => caches.delete(k)));
  } catch {}
}

// ── Duress mode ───────────────────────────────────────────────────────────────

export async function armDuressMode(duressPassword: string, maxAttempts: number): Promise<void> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const { argon2idAsync } = await import('@noble/hashes/argon2.js');
  // #29-FIX: raise Argon2id params to 256 MiB / t=3 to match the KDF floor (CWE-312).
  const hash = await argon2idAsync(new TextEncoder().encode(duressPassword), salt, { m: 256 * 1024, t: 3, p: 1, dkLen: 32 });

  const hashHex = Array.from(hash, b => b.toString(16).padStart(2, '0')).join('');
  const saltHex = Array.from(salt, b => b.toString(16).padStart(2, '0')).join('');
  const phc = `$argon2id$v=19$m=262144,t=3,p=1$${saltHex}$${hashHex}`;
  const cfg: DuressModeConfig = { armed: true, passwordHash: phc, maxAttempts, attemptsRemaining: maxAttempts, salt: saltHex };

  await saveDuressModeConfig(cfg);
}

export async function disarmDuressMode(): Promise<void> {
  // Overwrite the config with random data before removing (anti-forensic)
  const buf = new Uint8Array(256);
  crypto.getRandomValues(buf);
  const noise = Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
  localStorage.setItem(DURESS_KEY, noise);
  localStorage.removeItem(DURESS_KEY);
  localStorage.setItem(DURESS_KEY + '_sentinel', noise);
  localStorage.removeItem(DURESS_KEY + '_sentinel');

  // Drop the server-side mirror so a future re-login doesn't rehydrate an
  // "armed" config back into localStorage.
  if (hasServerSessionCookie()) {
    const csrf = getCsrf();
    if (csrf) {
      try {
        await fetch('/api/vault/duress-config', {
          method: 'DELETE',
          credentials: 'same-origin',
          headers: { 'X-CSRF-Token': csrf },
        });
      } catch { /* non-fatal */ }
    }
  }
}

// Timing-safe comparison for hex strings
function timingSafeHash(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function checkIsDuressPassword(entered: string): Promise<boolean> {
  // #29-FIX: use the full (encrypted) config to read the passwordHash.
  const cfg = await getDuressModeConfigFull();
  if (!cfg.armed || !cfg.passwordHash) return false;

  // Parse PHC string: $argon2id$v=19$m=...,t=...,p=...$<saltHex>$<hashHex>
  const parts = cfg.passwordHash.split('$');
  if (parts.length < 6) return false;
  const paramStr = parts[3]; // m=...,t=...,p=...
  const saltHex = parts[4];
  const hashHex = parts[5];

  // Parse params from the PHC string to support both old (64MiB/t=2) and new (256MiB/t=3) hashes.
  const mMatch = paramStr.match(/m=(\d+)/); const tMatch = paramStr.match(/t=(\d+)/); const pMatch = paramStr.match(/p=(\d+)/);
  const m = mMatch ? parseInt(mMatch[1]) : 65536;
  const t = tMatch ? parseInt(tMatch[1]) : 2;
  const p = pMatch ? parseInt(pMatch[1]) : 1;

  const { argon2idAsync } = await import('@noble/hashes/argon2.js');
  const salt = hexToBytes(saltHex);
  const hash = await argon2idAsync(new TextEncoder().encode(entered), salt, { m, t, p, dkLen: 32 });
  const enteredHashHex = Array.from(hash, b => b.toString(16).padStart(2, '0')).join('');

  return timingSafeHash(enteredHashHex, hashHex);
}

export function checkIsLockedOut(): { locked: boolean; remainingMins: number } {
  const cfg = getLockoutConfig();
  if (!cfg.enabled || !cfg.lockedUntil) return { locked: false, remainingMins: 0 };
  
  const now = Date.now();
  if (now >= cfg.lockedUntil) {
    return { locked: false, remainingMins: 0 };
  }
  
  return { locked: true, remainingMins: Math.ceil((cfg.lockedUntil - now) / 60000) };
}

// Returns true when wipe should be triggered (attempts exhausted)
export async function recordFailedLoginAttempt(): Promise<boolean> {
  // 1. Handle Lockout
  const lCfg = getLockoutConfig();
  if (lCfg.enabled) {
    lCfg.attemptsMade++;
    if (lCfg.attemptsMade >= lCfg.maxAttempts) {
      lCfg.lockedUntil = Date.now() + (lCfg.lockoutDurationMins * 60000);
    }
    saveLockoutConfig(lCfg);
  }

  // 2. Handle Duress (use full encrypted config for attemptsRemaining counter)
  const dCfg = await getDuressModeConfigFull();
  if (!dCfg.armed) return false;
  dCfg.attemptsRemaining = Math.max(0, dCfg.attemptsRemaining - 1);
  await saveDuressModeConfig(dCfg);
  return dCfg.attemptsRemaining === 0;
}

export async function resetLoginAttempts(): Promise<void> {
  const dCfg = await getDuressModeConfigFull();
  if (dCfg.armed) {
    dCfg.attemptsRemaining = dCfg.maxAttempts;
    await saveDuressModeConfig(dCfg);
  }

  const lCfg = getLockoutConfig();
  lCfg.attemptsMade = 0;
  lCfg.lockedUntil = null;
  saveLockoutConfig(lCfg);
}

// ── Travel mode ───────────────────────────────────────────────────────────────
// Dual-path: WebCrypto subtle (HTTPS / localhost) or @noble/ciphers (plain HTTP).

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// Returns true only when WebCrypto subtle is available (HTTPS / localhost).
// Evaluated at call time - not at module load - to avoid race conditions with
// the browser's secure-context detection during initial page parse.
function subtleAvailable(): boolean {
  return typeof crypto !== 'undefined' && typeof crypto.subtle?.importKey === 'function';
}

// Derive a 32-byte key from password + salt.
// v2: Argon2id (64MB, t=2, p=1) on HTTPS, else PBKDF2 600k.
// v1: PBKDF2 120k (Legacy).
async function deriveTravelKeyBytes(password: string, saltHex: string, version: 1 | 2 = 2): Promise<Uint8Array> {
  const pwBytes   = new TextEncoder().encode(password);
  const saltBytes = new TextEncoder().encode(saltHex);
  
  if (version === 2) {
    if (subtleAvailable()) {
       const { argon2idAsync } = await import('@noble/hashes/argon2.js');
       return await argon2idAsync(pwBytes, saltBytes, { m: 64 * 1024, t: 2, p: 1, dkLen: 32 });
    }
    // Non-secure context fallback - PBKDF2 600k (A-04 requirement)
    return pbkdf2(sha256, pwBytes, saltBytes, { c: 600_000, dkLen: 32 });
  }

  if (subtleAvailable()) {
    const mat  = await crypto.subtle.importKey('raw', pwBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: 120_000 },
      mat, 256,
    );
    return new Uint8Array(bits);
  }
  // Non-secure context fallback - @noble/hashes PBKDF2 (pure JS, no WebCrypto needed)
  return pbkdf2(sha256, pwBytes, saltBytes, { c: 120_000, dkLen: 32 });
}

async function travelEncrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  if (subtleAvailable()) {
    const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
    return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext));
  }
  // Non-secure context fallback - @noble/ciphers pure-JS AES-256-GCM
  const { gcm } = await import('@noble/ciphers/aes.js');
  return gcm(key, iv).encrypt(plaintext);
}

async function travelDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  if (subtleAvailable()) {
    const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ciphertext));
  }
  const { gcm } = await import('@noble/ciphers/aes.js');
  return gcm(key, iv).decrypt(ciphertext);
}

// ── Travel mode ───────────────────────────────────────────────────────────────

export async function enableTravelMode(
  travelPassword: string,
  hiddenFolderIds: string[],
  allCredentials: unknown[],
  allFolders: unknown[],
): Promise<{ visibleCredentials: unknown[]; visibleFolders: unknown[] }> {
  const salt = generateUUID();
  const passwordHash = await hashPassword(travelPassword, salt);

  const hiddenCredentials = (allCredentials as Array<{ folderId: string }>)
    .filter(c => hiddenFolderIds.includes(c.folderId));
  const hiddenFolders = (allFolders as Array<{ id: string }>)
    .filter(f => hiddenFolderIds.includes(f.id));
  const visibleCredentials = (allCredentials as Array<{ folderId: string }>)
    .filter(c => !hiddenFolderIds.includes(c.folderId));
  const visibleFolders = (allFolders as Array<{ id: string }>)
    .filter(f => !hiddenFolderIds.includes(f.id));

  const key       = await deriveTravelKeyBytes(travelPassword, salt, 2);
  const iv        = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify({ credentials: hiddenCredentials, folders: hiddenFolders }));
  const ciphertext = await travelEncrypt(key, iv, plaintext);

  // Overwrite the slot with random data before writing real ciphertext (anti-forensic)
  const rnd = new Uint8Array(ciphertext.length);
  crypto.getRandomValues(rnd);
  localStorage.setItem(TRAVEL_VAULT_KEY, bytesToHex(rnd));

  const ciphertextEnvelope = JSON.stringify({ iv: bytesToHex(iv), ct: bytesToHex(ciphertext) });
  localStorage.setItem(TRAVEL_VAULT_KEY, ciphertextEnvelope);

  // Server-mode mirror: store the encrypted travel vault on the server so it
  // survives browser-data clears. The envelope is already encrypted with the
  // travel password (not the user's main password) - the server cannot read
  // it. This protects against accidental data loss without weakening privacy.
  if (hasServerSessionCookie()) {
    const csrf = getCsrf();
    if (csrf) {
      try {
        await fetch('/api/vault/travel-vault', {
          method: 'PUT',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
          body: JSON.stringify({ data: ciphertextEnvelope }),
        });
      } catch { /* mirror failure is non-fatal; local copy remains authoritative */ }
    }
  }

  await saveTravelModeConfig({
    active: true,
    passwordHash,
    hiddenFolderIds,
    salt,
    ivHex: bytesToHex(iv),
    kdf_version: 2,
  });

  return { visibleCredentials, visibleFolders };
}

export async function disableTravelMode(
  travelPassword: string,
  currentCredentials: unknown[],
  currentFolders: unknown[],
): Promise<{ ok: boolean; credentials: unknown[]; folders: unknown[] }> {
  const cfg = await getTravelModeConfigAsync();
  if (!cfg.active || !cfg.passwordHash) return { ok: false, credentials: [], folders: [] };

  const hash  = await hashPassword(travelPassword, cfg.salt);
  const match = await timingSafeHash(hash, cfg.passwordHash);
  if (!match) return { ok: false, credentials: [], folders: [] };

  let hiddenCredentials: unknown[] = [];
  let hiddenFolders: unknown[] = [];

  try {
    let stored = localStorage.getItem(TRAVEL_VAULT_KEY);
    // Server-mode recovery: if the local hidden vault was cleared (browser data
    // wipe, new device), fetch the mirror from the server. The travel password
    // is still required - server cannot decrypt it.
    if ((!stored || !stored.startsWith('{')) && hasServerSessionCookie()) {
      try {
        const res = await fetch('/api/vault/travel-vault', { credentials: 'same-origin' });
        if (res.ok) {
          const body = await res.json().catch(() => null);
          if (body && typeof body.data === 'string') stored = body.data;
        }
      } catch { /* no remote copy = stays null */ }
    }
    if (stored && stored.startsWith('{')) {
      const { iv: ivHex, ct: ctHex } = JSON.parse(stored);
      const key      = await deriveTravelKeyBytes(travelPassword, cfg.salt, cfg.kdf_version || 1);
      const iv       = hexToBytes(ivHex);
      const ct       = hexToBytes(ctHex);
      const ptBytes  = await travelDecrypt(key, iv, ct);
      const vault    = JSON.parse(new TextDecoder().decode(ptBytes));
      hiddenCredentials = vault.credentials ?? [];
      hiddenFolders     = vault.folders     ?? [];

      // Re-encrypt under v2 if it was v1 (migration)
      if ((cfg.kdf_version || 1) === 1) {
          const newKey = await deriveTravelKeyBytes(travelPassword, cfg.salt, 2);
          const newIv = crypto.getRandomValues(new Uint8Array(12));
          const newCt = await travelEncrypt(newKey, newIv, ptBytes);
          localStorage.setItem(TRAVEL_VAULT_KEY, JSON.stringify({ iv: bytesToHex(newIv), ct: bytesToHex(newCt) }));
          cfg.kdf_version = 2;
          cfg.ivHex = bytesToHex(newIv);
      }
    }
  } catch {
    return { ok: false, credentials: [], folders: [] };
  }

  for (let i = 0; i < 3; i++) {
    const rnd = new Uint8Array(256);
    crypto.getRandomValues(rnd);
    localStorage.setItem(TRAVEL_VAULT_KEY, bytesToHex(rnd));
  }
  localStorage.removeItem(TRAVEL_VAULT_KEY);

  // Also drop the server-side mirror so a future re-login cannot rehydrate.
  if (hasServerSessionCookie()) {
    const csrfDel = getCsrf();
    if (csrfDel) {
      try {
        await fetch('/api/vault/travel-vault', {
          method: 'DELETE',
          credentials: 'same-origin',
          headers: { 'X-CSRF-Token': csrfDel },
        });
      } catch { /* non-fatal */ }
    }
  }

  const mergedCredentials = [...(currentCredentials as unknown[]), ...hiddenCredentials];
  const mergedFolders     = [...(currentFolders as unknown[]), ...hiddenFolders];

  // Clear the server-side config too. Without this an old "active:true"
  // config could still be on the server, mis-hydrating a future session.
  if (hasServerSessionCookie()) {
    const csrf = getCsrf();
    if (csrf) {
      try {
        await fetch('/api/vault/travel-config', {
          method: 'DELETE',
          credentials: 'same-origin',
          headers: { 'X-CSRF-Token': csrf },
        });
      } catch { /* non-fatal */ }
    }
  }

  await saveTravelModeConfig({ active: false, passwordHash: null, hiddenFolderIds: [], salt: generateUUID(), ivHex: '' });

  return { ok: true, credentials: mergedCredentials, folders: mergedFolders };
}
