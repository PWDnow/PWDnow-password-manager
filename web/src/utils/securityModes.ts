import { hashPassword, generateUUID } from './crypto';
import { WIPE_TICKET_KEY } from './daemonClient';
import { writeEncryptedLocal } from './localCrypto';
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
const TRAVEL_KEY = 'travel_mode_config';
// Intentionally generic-looking key so as not to draw attention during inspection
const TRAVEL_VAULT_KEY = '_cache_local_xvc';

// ── Config accessors ──────────────────────────────────────────────────────────

export function getDuressModeConfig(): DuressModeConfig {
  try {
    const s = localStorage.getItem(DURESS_KEY);
    if (s) return JSON.parse(s) as DuressModeConfig;
  } catch {}
  const salt = generateUUID();
  return { armed: false, passwordHash: null, maxAttempts: 5, attemptsRemaining: 5, salt };
}

function saveDuressModeConfig(cfg: DuressModeConfig): void {
  localStorage.setItem(DURESS_KEY, JSON.stringify(cfg));
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

export function getTravelModeConfig(): TravelModeConfig {
  try {
    const s = localStorage.getItem(TRAVEL_KEY);
    if (s) return JSON.parse(s) as TravelModeConfig;
  } catch {}
  return { active: false, passwordHash: null, hiddenFolderIds: [], salt: generateUUID(), ivHex: '' };
}

function saveTravelModeConfig(cfg: TravelModeConfig): void {
  localStorage.setItem(TRAVEL_KEY, JSON.stringify(cfg));
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
 * localStorage once with CSPRNG bytes before clearing.  Multi-pass overwrite is
 * not meaningful on browser-managed storage backed by SQLite/LevelDB on flash.
 * Then clears sessionStorage, all IndexedDB databases, and service-worker caches.
 */
export async function wipeVaultData(daemonInstance?: ForensicWipeable): Promise<void> {
  // Phase 1: daemon-side forensic wipe (files on disk)
  if (daemonInstance?.isConnected) {
    try {
      const ticketHex = localStorage.getItem(WIPE_TICKET_KEY);
      if (ticketHex && ticketHex.length === 64) {
        const ticket = hexToBytes(ticketHex);
        await daemonInstance.forensicWipe(ticket);
      }
    } catch { /* non-fatal - continue with browser wipe */ }
  }

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
  const hash = await argon2idAsync(new TextEncoder().encode(duressPassword), salt, { m: 64 * 1024, t: 2, p: 1, dkLen: 32 });
  
  const hashHex = Array.from(hash, b => b.toString(16).padStart(2, '0')).join('');
  const saltHex = Array.from(salt, b => b.toString(16).padStart(2, '0')).join('');
  // Store as PHC string: $argon2id$v=19$m=65536,t=2,p=1$<saltHex>$<hashHex>
  const phc = `$argon2id$v=19$m=65536,t=2,p=1$${saltHex}$${hashHex}`;

  saveDuressModeConfig({ armed: true, passwordHash: phc, maxAttempts, attemptsRemaining: maxAttempts, salt: saltHex });
}

export function disarmDuressMode(): void {
  // Overwrite the config with random data before removing (anti-forensic)
  const buf = new Uint8Array(256);
  crypto.getRandomValues(buf);
  localStorage.setItem(DURESS_KEY, Array.from(buf, b => b.toString(16).padStart(2, '0')).join(''));
  localStorage.removeItem(DURESS_KEY);
}

// Timing-safe comparison for hex strings
function timingSafeHash(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function checkIsDuressPassword(entered: string): Promise<boolean> {
  const cfg = getDuressModeConfig();
  if (!cfg.armed || !cfg.passwordHash) return false;
  
  // Parse PHC string
  const parts = cfg.passwordHash.split('$');
  if (parts.length < 6) return false;
  const saltHex = parts[4];
  const hashHex = parts[5];

  const { argon2idAsync } = await import('@noble/hashes/argon2.js');
  const salt = hexToBytes(saltHex);
  const hash = await argon2idAsync(new TextEncoder().encode(entered), salt, { m: 64 * 1024, t: 2, p: 1, dkLen: 32 });
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
export function recordFailedLoginAttempt(): boolean {
  // 1. Handle Lockout
  const lCfg = getLockoutConfig();
  if (lCfg.enabled) {
    lCfg.attemptsMade++;
    if (lCfg.attemptsMade >= lCfg.maxAttempts) {
      lCfg.lockedUntil = Date.now() + (lCfg.lockoutDurationMins * 60000);
    }
    saveLockoutConfig(lCfg);
  }

  // 2. Handle Duress
  const dCfg = getDuressModeConfig();
  if (!dCfg.armed) return false;
  dCfg.attemptsRemaining = Math.max(0, dCfg.attemptsRemaining - 1);
  saveDuressModeConfig(dCfg);
  return dCfg.attemptsRemaining === 0;
}

export function resetLoginAttempts(): void {
  const dCfg = getDuressModeConfig();
  if (dCfg.armed) {
    dCfg.attemptsRemaining = dCfg.maxAttempts;
    saveDuressModeConfig(dCfg);
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

  localStorage.setItem(TRAVEL_VAULT_KEY, JSON.stringify({ iv: bytesToHex(iv), ct: bytesToHex(ciphertext) }));

  await writeEncryptedLocal('vault_credentials', JSON.stringify(visibleCredentials));
  await writeEncryptedLocal('vault_folders', JSON.stringify(visibleFolders));

  saveTravelModeConfig({
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
  const cfg = getTravelModeConfig();
  if (!cfg.active || !cfg.passwordHash) return { ok: false, credentials: [], folders: [] };

  const hash  = await hashPassword(travelPassword, cfg.salt);
  const match = await timingSafeHash(hash, cfg.passwordHash);
  if (!match) return { ok: false, credentials: [], folders: [] };

  let hiddenCredentials: unknown[] = [];
  let hiddenFolders: unknown[] = [];

  try {
    const stored = localStorage.getItem(TRAVEL_VAULT_KEY);
    if (stored) {
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

  const mergedCredentials = [...(currentCredentials as unknown[]), ...hiddenCredentials];
  const mergedFolders     = [...(currentFolders as unknown[]), ...hiddenFolders];

  await writeEncryptedLocal('vault_credentials', JSON.stringify(mergedCredentials));
  await writeEncryptedLocal('vault_folders',     JSON.stringify(mergedFolders));

  for (let i = 0; i < 3; i++) {
    const rnd = new Uint8Array(256);
    crypto.getRandomValues(rnd);
    localStorage.setItem(TRAVEL_KEY, bytesToHex(rnd));
  }
  saveTravelModeConfig({ active: false, passwordHash: null, hiddenFolderIds: [], salt: generateUUID(), ivHex: '' });

  return { ok: true, credentials: mergedCredentials, folders: mergedFolders };
}
