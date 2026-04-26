import { hashPassword, generateUUID } from './crypto';
import { WIPE_TICKET_KEY } from './daemonClient';
import { writeEncryptedLocal } from './localCrypto';

export interface DuressModeConfig {
  armed: boolean;
  passwordHash: string | null;
  maxAttempts: number;
  attemptsRemaining: number;
  salt: string;
}

export interface TravelModeConfig {
  active: boolean;
  passwordHash: string | null;
  hiddenFolderIds: string[];
  salt: string;
  ivHex: string;
}

const DURESS_KEY = 'duress_mode_config';
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
 * Phase 1 (daemon, when connected): sends ForensicWipe to the daemon, which
 * does a 7-pass overwrite of vault.db + vault.db.meta, destroys the Argon2
 * salt, and exits.  Without the salt no KEK can be derived — the ciphertext
 * is permanently unrecoverable even with the correct password.
 *
 * Phase 2 (browser): 3-pass CSPRNG overwrite of every localStorage key,
 * clear localStorage / sessionStorage, delete all IndexedDB databases, and
 * purge all service-worker caches.
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
    } catch { /* non-fatal — continue with browser wipe */ }
  }

  const keys = Object.keys(localStorage);

  // Three passes of cryptographically random overwrite
  for (let pass = 0; pass < 3; pass++) {
    for (const key of keys) {
      try {
        const buf = new Uint8Array(512);
        crypto.getRandomValues(buf);
        localStorage.setItem(key, Array.from(buf, b => b.toString(16).padStart(2, '0')).join(''));
      } catch {}
    }
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
  const salt = generateUUID();
  const hash = await hashPassword(duressPassword, salt);
  saveDuressModeConfig({ armed: true, passwordHash: hash, maxAttempts, attemptsRemaining: maxAttempts, salt });
}

export function disarmDuressMode(): void {
  // Overwrite the config with random data before removing (anti-forensic)
  const buf = new Uint8Array(256);
  crypto.getRandomValues(buf);
  localStorage.setItem(DURESS_KEY, Array.from(buf, b => b.toString(16).padStart(2, '0')).join(''));
  localStorage.removeItem(DURESS_KEY);
}

// Timing-safe comparison
async function timingSafeHash(a: string, b: string): Promise<boolean> {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function checkIsDuressPassword(entered: string): Promise<boolean> {
  const cfg = getDuressModeConfig();
  if (!cfg.armed || !cfg.passwordHash) return false;
  const hash = await hashPassword(entered, cfg.salt);
  return timingSafeHash(hash, cfg.passwordHash);
}

// Returns true when wipe should be triggered (attempts exhausted)
export function recordFailedLoginAttempt(): boolean {
  const cfg = getDuressModeConfig();
  if (!cfg.armed) return false;
  cfg.attemptsRemaining = Math.max(0, cfg.attemptsRemaining - 1);
  saveDuressModeConfig(cfg);
  return cfg.attemptsRemaining === 0;
}

export function resetLoginAttempts(): void {
  const cfg = getDuressModeConfig();
  if (cfg.armed) {
    cfg.attemptsRemaining = cfg.maxAttempts;
    saveDuressModeConfig(cfg);
  }
}

// ── Travel mode crypto ─────────────────────────────────────────────────────────
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
// Evaluated at call time — not at module load — to avoid race conditions with
// the browser's secure-context detection during initial page parse.
function subtleAvailable(): boolean {
  return typeof crypto !== 'undefined' && typeof crypto.subtle?.importKey === 'function';
}

// Derive a 32-byte key from password + salt using PBKDF2-SHA256 (120 000 iterations).
async function deriveTravelKeyBytes(password: string, saltHex: string): Promise<Uint8Array> {
  const pwBytes   = new TextEncoder().encode(password);
  const saltBytes = new TextEncoder().encode(saltHex);
  if (subtleAvailable()) {
    const mat  = await crypto.subtle.importKey('raw', pwBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: 120_000 },
      mat, 256,
    );
    return new Uint8Array(bits);
  }
  // Non-secure context fallback — @noble/hashes PBKDF2 (pure JS, no WebCrypto needed)
  const { pbkdf2 } = await import('@noble/hashes/pbkdf2.js');
  const { sha256 }  = await import('@noble/hashes/sha2.js');
  return pbkdf2(sha256, pwBytes, saltBytes, { c: 120_000, dkLen: 32 });
}

async function travelEncrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  if (subtleAvailable()) {
    const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
    return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext));
  }
  // Non-secure context fallback — @noble/ciphers pure-JS AES-256-GCM
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

// Offline/demo mode is single-user-per-browser; mirrors VaultContext's LOCAL_SUFFIX.
const LOCAL_SUFFIX = '';

export async function enableTravelMode(
  travelPassword: string,
  hiddenFolderIds: string[],
  allCredentials: unknown[],
  allFolders: unknown[],
): Promise<void> {
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

  const key       = await deriveTravelKeyBytes(travelPassword, salt);
  const iv        = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify({ credentials: hiddenCredentials, folders: hiddenFolders }));
  const ciphertext = await travelEncrypt(key, iv, plaintext);

  // Overwrite the slot with random data before writing real ciphertext (anti-forensic)
  const rnd = new Uint8Array(ciphertext.length);
  crypto.getRandomValues(rnd);
  localStorage.setItem(TRAVEL_VAULT_KEY, bytesToHex(rnd));

  localStorage.setItem(TRAVEL_VAULT_KEY, JSON.stringify({ iv: bytesToHex(iv), ct: bytesToHex(ciphertext) }));

  await writeEncryptedLocal(`vault_credentials${LOCAL_SUFFIX}`, JSON.stringify(visibleCredentials));
  await writeEncryptedLocal(`vault_folders${LOCAL_SUFFIX}`, JSON.stringify(visibleFolders));

  saveTravelModeConfig({
    active: true,
    passwordHash,
    hiddenFolderIds,
    salt,
    ivHex: bytesToHex(iv),
  });
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
      const key      = await deriveTravelKeyBytes(travelPassword, cfg.salt);
      const iv       = hexToBytes(ivHex);
      const ct       = hexToBytes(ctHex);
      const ptBytes  = await travelDecrypt(key, iv, ct);
      const vault    = JSON.parse(new TextDecoder().decode(ptBytes));
      hiddenCredentials = vault.credentials ?? [];
      hiddenFolders     = vault.folders     ?? [];
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

  await writeEncryptedLocal(`vault_credentials${LOCAL_SUFFIX}`, JSON.stringify(mergedCredentials));
  await writeEncryptedLocal(`vault_folders${LOCAL_SUFFIX}`,     JSON.stringify(mergedFolders));

  for (let i = 0; i < 3; i++) {
    const rnd = new Uint8Array(256);
    crypto.getRandomValues(rnd);
    localStorage.setItem(TRAVEL_KEY, bytesToHex(rnd));
  }
  saveTravelModeConfig({ active: false, passwordHash: null, hiddenFolderIds: [], salt: generateUUID(), ivHex: '' });

  return { ok: true, credentials: mergedCredentials, folders: mergedFolders };
}
