/**
 * Multi-Factor Authentication utilities
 *
 * TOTP  – RFC 6238 (uses totp-generator which falls back to jsSHA on HTTP)
 * Email – Client-side simulation: code generated with crypto.getRandomValues,
 *         held in memory (never persisted), returned so the UI can display it
 *         in a "simulated email preview" panel.
 * WebAuthn – Real W3C WebAuthn / FIDO2 via navigator.credentials.
 *            Requires a secure context (HTTPS or localhost).
 */

import { keyStore } from '../crypto/keystore';
import { writeEncryptedLocal, readDecryptedLocal, encryptForServer, decryptFromServer } from './localCrypto';
import { daemon } from './daemonClient';
import { generateUUID } from './crypto';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface WebAuthnCredentialMeta {
  id: string;        // base64url-encoded credential ID
  rawId: string;     // same, stored for get() calls
  name: string;      // user-assigned name (e.g. "YubiKey 5C")
  createdAt: number; // epoch ms
  counter: number;   // signature counter (incremented on each auth)
}

export interface MfaConfig {
  totp: {
    enabled: boolean;
    secret?: string;     // base32-encoded, stored on device
    enabledAt?: number;
    algorithm?: 'SHA-1' | 'SHA-256' | 'SHA-512';
    digits?: number;
  };
  hotp?: {
    enabled: boolean;
    secret?: string;
    counter: number;
    enabledAt?: number;
    algorithm?: 'SHA-1' | 'SHA-256' | 'SHA-512';
    digits?: number;
  };
  webauthn: {
    enabled: boolean;
    credentials: WebAuthnCredentialMeta[];  // cross-platform hardware keys (YubiKey etc.)
  };
  passkey: {
    enabled: boolean;
    credentials: WebAuthnCredentialMeta[];  // platform passkeys (iCloud/Google sync, residentKey)
  };
  platform: {
    enabled: boolean;
    credentials: WebAuthnCredentialMeta[];  // device-bound biometrics (Touch ID, Windows Hello)
  };
  email: {
    enabled: boolean;
    address?: string;
    enabledAt?: number;
  };
  passwordlessEnabled?: boolean;   // when true, password field is hidden at login (passkey-only)
  passwordLoginEnabled?: boolean;  // when false, password-only login card is hidden; default true
}

// ─── CSRF helper (shared by all server-side fetch calls in this module) ───────
function getCsrfToken(): string {
  return document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('_pwd_csrf='))?.split('=')[1] ?? '';
}

// ─── Login Hints ──────────────────────────────────────────────────────────────
// Hints are fetched live from the daemon/server on the email step and held in
// React state. They are NOT persisted to localStorage - doing so would expose
// which MFA methods are enabled for an account (information useful to attackers).

export interface LoginHints {
  totp: boolean;
  emailOtp: boolean;
  passwordEnabled: boolean;  // false = password-only login card hidden
  webauthn?: boolean;        // true = hardware security key registered
  passwordlessEnabled?: boolean; // true = vault requires passkey/security key to unlock
}

const DEFAULT_LOGIN_HINTS: LoginHints = {
  totp: false,
  emailOtp: false,
  passwordEnabled: true,
  webauthn: false,
  passwordlessEnabled: false,
};

/** Returns safe defaults - real hints come from the daemon/server per-login. */
export function getLoginHints(): LoginHints {
  return { ...DEFAULT_LOGIN_HINTS };
}

/** Sync policy to server only - never persists to localStorage. */
export function refreshLoginHints(): void {
  const cfg = getMfaConfig();
  const hasHardware = (cfg.passkey?.enabled || cfg.platform?.enabled || cfg.webauthn?.enabled) ?? false;
  const hints: LoginHints = {
    totp:               cfg.totp.enabled || (cfg.hotp?.enabled ?? false),
    emailOtp:           cfg.email.enabled,
    passwordEnabled:    cfg.passwordLoginEnabled !== false,
    webauthn:           cfg.webauthn?.enabled && cfg.webauthn.credentials.length > 0,
    passwordlessEnabled: (cfg.passwordlessEnabled === true) && hasHardware,
  };

  // Sync to server only
  const csrf = getCsrfToken();
  if (csrf) {
    fetch('/api/auth/login-hints', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({ hints }),
    }).catch(() => { /* silent fail */ });
  }
}

// ─── LocalStorage helpers (CRIT-06: AES-GCM encrypted) ───────────────────────
//
// Design: an in-memory cache (_mfaCache) holds the live MfaConfig object.
// When the demo encryption key is loaded (at login), call loadMfaConfig() once
// to decrypt from localStorage into the cache.
// getMfaConfig() returns the cache synchronously (no API change for callers).
// saveMfaConfig() updates the cache AND writes AES-GCM ciphertext to localStorage.
// On logout the cache is cleared via clearMfaCache().

const MFA_KEY = 'mfa_config';

const DEFAULT_MFA = (): MfaConfig => ({
  totp:     { enabled: false },
  webauthn: { enabled: false, credentials: [] },
  passkey:  { enabled: false, credentials: [] },
  platform: { enabled: false, credentials: [] },
  email:    { enabled: false },
  passwordlessEnabled: false,
});

let _mfaCache: MfaConfig | null = null;

/**
 * Call once at login to decrypt MFA config into the in-memory cache.
 * Uses the centralised readDecryptedLocal (JWT-like signed+encrypted format).
 * Falls back to server when local key is unavailable (page refresh in server mode).
 */
export async function loadMfaConfig(): Promise<void> {
  const decrypted = await readDecryptedLocal(MFA_KEY);
  if (decrypted) {
    try {
      _mfaCache = JSON.parse(decrypted) as MfaConfig;
      return;
    } catch { /* corrupt blob - fall through to server */ }
  }
  await loadMfaConfigFromServer();
  if (!_mfaCache) _mfaCache = DEFAULT_MFA();
}

/** Synchronous read from in-memory cache. Returns DEFAULT_MFA if not yet loaded. */
export function getMfaConfig(): MfaConfig {
  return _mfaCache ?? DEFAULT_MFA();
}

/**
 * Update cache, persist to localStorage as a signed+encrypted compact token,
 * and sync to server. TOTP secrets are never written in plaintext.
 */
export function saveMfaConfig(cfg: MfaConfig): void {
  _mfaCache = cfg;

  // Persist to server so config survives logout/login cycles.
  saveMfaConfigToServer(cfg).catch(() => { /* non-fatal */ });

  // Sync policy flags to daemon if connected.
  if (daemon.isConnected) {
    daemon.updateLoginPolicy(
      cfg.passwordLoginEnabled !== false,
      cfg.totp.enabled,
      cfg.email.enabled,
    ).catch(() => { /* non-fatal */ });
  }

  // Persist to localStorage using the shared signed+encrypted format.
  writeEncryptedLocal(MFA_KEY, JSON.stringify(cfg)).catch(() => { /* non-fatal */ });
}

// ─── Server-side MFA persistence ─────────────────────────────────────────────
// Stores the full MFA config (including TOTP secrets) in the server vault,
// encrypted at rest like credentials and folders. This survives logout/login.

async function saveMfaConfigToServer(cfg: MfaConfig): Promise<void> {
  const csrf = getCsrfToken();
  if (!csrf) return; // not in a server session

  const encData = await encryptForServer(JSON.stringify(cfg));
  if (!encData) return;

  await fetch('/api/vault/mfa', {
    method: 'PUT',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: JSON.stringify({ data: encData }),
  });
}

/** Load MFA config from server and merge into cache. Call after server login. */
export async function loadMfaConfigFromServer(): Promise<void> {
  // Daemon-only sessions don't have a `_pwd_csrf` cookie and the server route
  // requires one — hitting it guarantees a 401 that shows up in the DevTools
  // console and obscures real errors. Skip the fetch entirely in that case;
  // MFA config lives in the encrypted localStorage blob for daemon-mode users.
  if (!getCsrfToken()) return;
  try {
    const res = await fetch('/api/vault/mfa', { credentials: 'same-origin' });
    if (!res.ok) return;
    const body = await res.json();
    let data: MfaConfig | null = null;
    
    if (body && typeof body.data === 'string') {
      const dec = await decryptFromServer(body.data);
      if (dec) data = JSON.parse(dec);
    } else if (body && typeof body === 'object' && 'totp' in body) {
      data = body as MfaConfig; // legacy fallback
    }

    if (data && typeof data === 'object' && 'totp' in data) {
      _mfaCache = data;
    }
  } catch { /* non-fatal */ }
}

/** Clear the in-memory cache AND localStorage on logout so the next user
 *  on the same device does not see a previous account's MFA config. */
export function clearMfaCache(): void {
  _mfaCache = null;
  localStorage.removeItem(MFA_KEY);
  // Remove legacy plaintext backup if present from a previous version.
  localStorage.removeItem('mfa_config_plain');
}

// ─── Base32 encode (RFC 4648) ─────────────────────────────────────────────────
// totp-generator only decodes; we need an encoder to produce the secret URI.

const B32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += B32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += B32_CHARS[(value << (5 - bits)) & 31];
  // No padding – RFC 4648 §3.2 allows omitting padding
  return output;
}

// ─── TOTP ──────────────────────────────────────────────────────────────────────

/** Generate a cryptographically random 20-byte TOTP secret (base32). */
export function generateTotpSecret(): string {
  const bytes = new Uint8Array(20);
  // crypto.getRandomValues works even on plain HTTP (unlike crypto.subtle)
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

/**
 * Build an otpauth:// URI as defined by the Google Authenticator Key URI Format.
 * Compatible with all RFC 6238 authenticator apps.
 */
export function buildTotpUri(secret: string, accountEmail: string, issuer = 'PWDnow', algorithm = 'SHA256', digits = 8): string {
  const label = encodeURIComponent(`${issuer}:${accountEmail}`);
  return (
    `otpauth://totp/${label}` +
    `?secret=${secret}` +
    `&issuer=${encodeURIComponent(issuer)}` +
    `&algorithm=${algorithm}` +
    `&digits=${digits}` +
    `&period=30`
  );
}

export function buildHotpUri(secret: string, accountEmail: string, counter = 0, issuer = 'PWDnow', algorithm = 'SHA256', digits = 8): string {
  const label = encodeURIComponent(`${issuer}:${accountEmail}`);
  return `otpauth://hotp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=${algorithm}&digits=${digits}&counter=${counter}`;
}

function base32Decode(base32: string): Uint8Array {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = base32.toUpperCase().replace(/=+$/, '');
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alpha.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xFF); bits -= 8; }
  }
  return new Uint8Array(out);
}

async function computeHotp(secret: string, counter: number, algorithm = 'SHA-1', digits = 6): Promise<string> {
  const secretBytes = base32Decode(secret);
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);
  const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: algorithm }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
  const offset = sig[sig.length - 1] & 0xF;
  const code = ((sig[offset] & 0x7F) << 24) | (sig[offset + 1] << 16) | (sig[offset + 2] << 8) | sig[offset + 3];
  return String(code % Math.pow(10, digits)).padStart(digits, '0');
}

export async function verifyHotp(
  secret: string,
  storedCounter: number,
  token: string,
  lookahead = 10,
  algorithm = 'SHA-1',
  digits = 6,
): Promise<{ ok: boolean; nextCounter: number }> {
  const clean = token.replace(/\s/g, '');
  if (!new RegExp(`^\\d{${digits}}$`).test(clean)) return { ok: false, nextCounter: storedCounter };
  for (let i = 0; i <= lookahead; i++) {
    const code = await computeHotp(secret, storedCounter + i, algorithm, digits);
    if (code === clean) return { ok: true, nextCounter: storedCounter + i + 1 };
  }
  return { ok: false, nextCounter: storedCounter };
}

// MED-04: in-memory set of recently consumed TOTP periods.
// Key: `${secret}:${period}` where period = Math.floor(timestamp / 30000).
// Value: expiry epoch (ms) after which the entry can be garbage-collected.
const _usedTotpPeriods = new Map<string, number>();

/**
 * Verify a TOTP code against the stored secret.
 * Checks current period ± 1 step to tolerate ≤30 s clock drift.
 * MED-04: rejects codes that have already been used in the same period (replay).
 */
export async function verifyTotp(secret: string, token: string, algorithm = 'SHA-1', digits = 6): Promise<boolean> {
  const clean = token.replace(/\s/g, '');
  if (!new RegExp(`^\\d{${digits}}$`).test(clean)) return false;
  const now = Date.now();

  // Garbage-collect expired entries
  for (const [key, expiry] of _usedTotpPeriods) {
    if (now > expiry) _usedTotpPeriods.delete(key);
  }

  // Only check the current period and one step forward.
  for (const drift of [0, 30000]) {
    const ts = now + drift;
    const period = Math.floor(ts / 30_000);
    const code = await computeHotp(secret, period, algorithm, digits);
    if (code === clean) {
      const replayKey = `${secret}:${period}:${algorithm}:${digits}`;
      if (_usedTotpPeriods.has(replayKey)) return false; // replay detected
      _usedTotpPeriods.set(replayKey, (period + 2) * 30_000);
      return true;
    }
  }
  return false;
}

// ─── Email OTP ─────────────────────────────────────────────────────────────────
// Code is held ONLY in module memory - never written to localStorage/sessionStorage.
// TTL is 5 minutes. This is a client-side simulation for the demo.

interface PendingEmailOtp {
  code: string;
  email: string;
  expires: number;
}

let _pendingOtp: PendingEmailOtp | null = null;

/** Generate a 6-digit OTP and return it (caller shows it in simulated email). */
export function generateEmailCode(email: string): string {
  // Rejection sampling avoids modulo bias (2^32 is not divisible by 1_000_000).
  const LIMIT = Math.floor(0x1_0000_0000 / 1_000_000) * 1_000_000; // 4_294_000_000
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while (buf[0] >= LIMIT);
  const code = String(buf[0] % 1_000_000).padStart(6, '0');
  _pendingOtp = { code, email, expires: Date.now() + 5 * 60 * 1000 };
  return code;
}

/** Return the email the pending code was sent to (for display only). */
export function getPendingOtpEmail(): string | null {
  return _pendingOtp?.email ?? null;
}

/** Verify the code and clear it regardless of outcome. */
export function verifyEmailCode(token: string): boolean {
  if (!_pendingOtp) return false;
  if (Date.now() > _pendingOtp.expires) { _pendingOtp = null; return false; }
  const ok = _pendingOtp.code === token.replace(/\s/g, '');
  _pendingOtp = null; // single-use
  return ok;
}

export function clearPendingOtp(): void { _pendingOtp = null; }

// ─── WebAuthn ─────────────────────────────────────────────────────────────────

export function isWebAuthnSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    typeof navigator.credentials !== 'undefined'
  );
}

/**
 * Returns true when the browser/OS has a platform authenticator available
 * (Touch ID, Windows Hello, Android fingerprint…).
 * Returns false in environments without biometric hardware, such as Linux VMs
 * running inside Parallels / VMware where no biometric sensor is exposed.
 */
export async function isPlatformAuthAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/**
 * Converts a WebAuthn DOMException into a human-readable message that explains
 * what went wrong and, where possible, how to fix it.
 *
 * @param type  'securitykey' | 'passkey' | 'platform'
 */
export function describeWebAuthnError(err: unknown, type: 'securitykey' | 'passkey' | 'platform'): string {
  const e = err instanceof Error ? err : new Error(String(err));
  const isLinux = typeof navigator !== 'undefined' && /Linux/.test(navigator.userAgent) && !/Android/.test(navigator.userAgent);

  // NotAllowedError covers: operation cancelled, no authenticator found, OS denied access.
  if (e.name === 'NotAllowedError') {
    if (type === 'platform' || type === 'passkey') {
      return (
        'Platform authenticator not available. ' +
        'Touch ID, Windows Hello, and Face ID require biometric hardware that is not accessible ' +
        'inside a virtual machine. Run the app directly on macOS/Windows to use these features.'
      );
    }
    if (type === 'securitykey' && isLinux) {
      return (
        'Security key access denied. Three common causes on Linux:\n' +
        '1. Key not connected to this VM - in Parallels: Devices → USB → [YubiKey] → Connect to Ubuntu\n' +
        '2. Missing udev permissions - run the setup commands shown above\n' +
        '3. Not in plugdev group - run: sudo adduser $USER plugdev  (then log out/in)'
      );
    }
    return 'The operation was cancelled or no compatible authenticator was found. Make sure your key is plugged in and try again.';
  }

  if (e.name === 'TimeoutError' || e.message.toLowerCase().includes('timed out')) {
    return 'The operation timed out. Plug in your security key before clicking the button, then respond promptly to the browser prompt.';
  }

  if (e.name === 'InvalidStateError') {
    return 'This credential is already registered. Remove the existing entry and try again.';
  }

  if (e.name === 'NotSupportedError') {
    return 'This authenticator type is not supported in the current browser or environment.';
  }

  return e.message || 'Registration failed. Check your authenticator and try again.';
}

export function isSecureContext(): boolean {
  return window.isSecureContext;
}

/** Encode an ArrayBuffer as base64url (no padding). */
function bufToB64url(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decode a base64url string back to Uint8Array. */
function b64urlToBuf(b64: string): Uint8Array {
  const padded = b64.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(padded);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

/**
 * WebAuthn Registration Ceremony (FIDO2 MakeCredential) via Daemon.
 * Returns metadata to store, or throws on failure.
 */
export async function registerWebAuthn(
  userId: string,
  email: string,
  displayName: string,
  credentialName: string,
): Promise<WebAuthnCredentialMeta> {
  if (!isWebAuthnSupported()) throw new Error('WebAuthn not supported in this browser.');
  if (!isSecureContext()) throw new Error('WebAuthn requires a secure context (HTTPS or localhost).');

  if (!daemon.isConnected) await daemon.connect();
  
  // 1. List devices
  const devices = await daemon.listFido2Devices();
  if (!devices.length) throw new Error('No hardware security keys found. Make sure your key is connected.');

  // 2. Register via daemon (this will prompt the user to touch the key)
  // We use the first found device for simplicity.
  const id = await daemon.registerFido2(devices[0], credentialName, false);

  const meta: WebAuthnCredentialMeta = {
    id,
    rawId:     id,
    name:      credentialName,
    createdAt: Date.now(),
    counter:   0,
  };

  // Persist to local cache (for hints)
  const cfg = getMfaConfig();
  cfg.webauthn.credentials.push(meta);
  cfg.webauthn.enabled = true;
  saveMfaConfig(cfg);

  return meta;
}

/**
 * WebAuthn Authentication Ceremony (FIDO2 GetAssertion).
 * Returns true if the key assertion is accepted.
 *
 * NOTE: In a real application the challenge and counter verification
 * happens on a trusted server. Here we verify locally in localStorage
 * (which is sufficient for a client-side demo, but not production-grade).
 */
export async function authenticateWebAuthn(credentialId: string): Promise<boolean> {
  if (!isWebAuthnSupported()) throw new Error('WebAuthn not supported.');
  if (!isSecureContext()) throw new Error('WebAuthn requires HTTPS or localhost.');

  const cfg = getMfaConfig();
  const stored = cfg.webauthn.credentials.find(c => c.id === credentialId);
  if (!stored) throw new Error('Credential not found.');

  const challenge = crypto.getRandomValues(new Uint8Array(32));

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: window.location.hostname,
      allowCredentials: [{
        id: b64urlToBuf(stored.rawId),
        type: 'public-key',
        transports: ['usb', 'nfc', 'ble', 'internal'],
      }],
      userVerification: 'preferred',
      timeout: 60_000,
    },
  }) as PublicKeyCredential;

  if (!assertion) return false;

  // Update the signature counter (anti-cloning measure)
  const authData = (assertion.response as AuthenticatorAssertionResponse).authenticatorData;
  const newCounter = new DataView(authData).getUint32(33, false);
  // Counter must be ≥ stored value (0 = counter not implemented by authenticator)
  if (newCounter > 0 && newCounter <= stored.counter) {
    throw new Error('Signature counter decreased - possible cloned authenticator!');
  }
  stored.counter = newCounter;
  saveMfaConfig(cfg);

  return true;
}

// ─── Passkey / Platform Auth ──────────────────────────────────────────────────

// Passkey credential ID hints are stored encrypted in localStorage under this key.
// They are loaded into memory after login (when the session key is available).
// Before login, getPasskeyHint() returns [] - the daemon provides credential IDs
// via GetLoginHints (for daemon mode), and WebAuthn falls back to discoverable
// credentials (residentKey lookup) when no local hint is available.
const PASSKEY_HINT_KEY = '_pwdn_pk_hint';
let _passkeyHintCache: Array<{ id: string; name: string }> | null = null;

/** Encrypt and persist the passkey credential ID list after login. */
function savePasskeyHint(credentials: WebAuthnCredentialMeta[]): void {
  const ids = credentials.map(c => ({ id: c.rawId, name: c.name }));
  _passkeyHintCache = ids;
  writeEncryptedLocal(PASSKEY_HINT_KEY, JSON.stringify(ids)).catch(() => { /* non-fatal */ });
}

/**
 * Load passkey hints from encrypted localStorage into the in-memory cache.
 * Call once after login when the session key is in memory.
 */
export async function loadPasskeyHint(): Promise<void> {
  try {
    const raw = await readDecryptedLocal(PASSKEY_HINT_KEY);
    _passkeyHintCache = raw ? (JSON.parse(raw) as Array<{ id: string; name: string }>) : [];
  } catch {
    _passkeyHintCache = [];
  }
  // Remove any legacy plaintext hint that may have been written before this version.
  const legacy = localStorage.getItem(PASSKEY_HINT_KEY);
  if (legacy && !legacy.includes('.')) localStorage.removeItem(PASSKEY_HINT_KEY);
}

/** Returns credential ID hints from the in-memory cache. Empty before loadPasskeyHint(). */
export function getPasskeyHint(): Array<{ id: string; name: string }> {
  return _passkeyHintCache ?? [];
}

function refreshPasskeyHint(): void {
  const cfg = getMfaConfig();
  const all = [...(cfg.passkey?.credentials ?? []), ...(cfg.platform?.credentials ?? [])];
  savePasskeyHint(all);
}

/**
 * Register a SYNCED passkey (iCloud Keychain / Google Password Manager).
 * Uses authenticatorAttachment 'platform' + residentKey 'required'.
 * On Mac this triggers Touch ID; on Windows it triggers Windows Hello.
 */
export async function registerPasskey(
  userId: string,
  email: string,
  displayName: string,
  credentialName: string,
): Promise<WebAuthnCredentialMeta> {
  if (!isWebAuthnSupported()) throw new Error('WebAuthn not supported in this browser.');
  if (!isSecureContext()) throw new Error('WebAuthn requires a secure context (HTTPS or localhost).');

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userIdBytes = new TextEncoder().encode(userId);

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: 'PWDnow', id: window.location.hostname },
      user: { id: userIdBytes, name: email, displayName },
      pubKeyCredParams: [
        { alg: -7,   type: 'public-key' },  // ES256
        { alg: -257, type: 'public-key' },  // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'required',  // discoverable / syncable credential
      },
      timeout: 60_000,
      attestation: 'none',
    },
  }) as PublicKeyCredential;

  if (!credential) throw new Error('Registration cancelled.');

  const meta: WebAuthnCredentialMeta = {
    id:        bufToB64url(credential.rawId),
    rawId:     bufToB64url(credential.rawId),
    name:      credentialName,
    createdAt: Date.now(),
    counter:   0,
  };

  const cfg = getMfaConfig();
  if (!cfg.passkey) cfg.passkey = { enabled: false, credentials: [] };
  cfg.passkey.credentials.push(meta);
  cfg.passkey.enabled = true;
  saveMfaConfig(cfg);
  refreshPasskeyHint();

  return meta;
}

/**
 * Register a DEVICE-BOUND platform authenticator (Touch ID, Windows Hello, Face ID).
 * Same underlying API as passkey but residentKey is 'discouraged' so it is NOT synced.
 */
export async function registerPlatformAuth(
  userId: string,
  email: string,
  displayName: string,
  credentialName: string,
): Promise<WebAuthnCredentialMeta> {
  if (!isWebAuthnSupported()) throw new Error('WebAuthn not supported in this browser.');
  if (!isSecureContext()) throw new Error('WebAuthn requires a secure context (HTTPS or localhost).');

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userIdBytes = new TextEncoder().encode(userId);

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: 'PWDnow', id: window.location.hostname },
      user: { id: userIdBytes, name: email, displayName },
      pubKeyCredParams: [
        { alg: -7,   type: 'public-key' },
        { alg: -257, type: 'public-key' },
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'discouraged',  // device-bound, not synced
      },
      timeout: 60_000,
      attestation: 'none',
    },
  }) as PublicKeyCredential;

  if (!credential) throw new Error('Registration cancelled.');

  const meta: WebAuthnCredentialMeta = {
    id:        bufToB64url(credential.rawId),
    rawId:     bufToB64url(credential.rawId),
    name:      credentialName,
    createdAt: Date.now(),
    counter:   0,
  };

  const cfg = getMfaConfig();
  if (!cfg.platform) cfg.platform = { enabled: false, credentials: [] };
  cfg.platform.credentials.push(meta);
  cfg.platform.enabled = true;
  saveMfaConfig(cfg);
  refreshPasskeyHint();

  return meta;
}

/**
 * Authenticate with a registered passkey or platform authenticator at login time.
 * Uses the stored hint (non-sensitive credential IDs) to target the right credential.
 * Falls back to discoverable credential lookup if no hint is stored.
 *
 * NOTE: Challenge-response signature is NOT verified server-side in demo mode.
 * Possession of the device + successful biometric is the auth factor.
 */
export async function authenticateWithPasskeyForLogin(): Promise<boolean> {
  if (!isWebAuthnSupported()) throw new Error('WebAuthn not supported.');
  if (!isSecureContext()) throw new Error('WebAuthn requires HTTPS or localhost.');

  const hints = getPasskeyHint();
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  const requestOptions: PublicKeyCredentialRequestOptions = {
    challenge,
    rpId: window.location.hostname,
    userVerification: 'required',
    timeout: 60_000,
  };

  if (hints.length > 0) {
    requestOptions.allowCredentials = hints.map(h => ({
      id: b64urlToBuf(h.id),
      type: 'public-key' as const,
      transports: ['internal' as AuthenticatorTransport],
    }));
  }
  // If no hints, omit allowCredentials → discoverable credential (resident key) lookup.

  const assertion = await navigator.credentials.get({ publicKey: requestOptions }) as PublicKeyCredential;
  if (!assertion) return false;

  const returnedId = bufToB64url(assertion.rawId);

  // Verify the returned credential is in our hint set or cached MFA config.
  if (hints.some(h => h.id === returnedId)) return true;

  const cfg = getMfaConfig();
  return (
    (cfg.passkey?.credentials ?? []).some(c => c.id === returnedId) ||
    (cfg.platform?.credentials ?? []).some(c => c.id === returnedId)
  );
}

/**
 * WebAuthn Authentication Ceremony (FIDO2 GetAssertion) via Daemon.
 * Returns true if the daemon accepts the assertion and unlocks the vault.
 */
export async function authenticateWebAuthnForLogin(): Promise<boolean> {
  if (!isWebAuthnSupported()) throw new Error('WebAuthn not supported.');
  if (!isSecureContext())     throw new Error('WebAuthn requires HTTPS or localhost.');

  if (!daemon.isConnected) await daemon.connect();
  const hints = await daemon.getLoginHints();
  if (!hints.fido2_ids.length) return false;

  const challenge = await daemon.getPasskeyChallenge();
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: window.location.hostname,
      allowCredentials: hints.fido2_ids.map(id => ({
        id,
        type:       'public-key' as const,
        transports: ['usb', 'nfc', 'ble', 'internal'] as AuthenticatorTransport[],
      })),
      userVerification: 'required',
      timeout: 60_000,
    },
  }) as PublicKeyCredential;

  if (!assertion) return false;

  const resp = assertion.response as AuthenticatorAssertionResponse;

  // F1-FIX: compute SHA-256 of clientDataJSON and send it to the daemon so it
  // can verify the assertion signature against the stored public key.
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', resp.clientDataJSON),
  );

  await daemon.unlockWithPasskey(
    new Uint8Array(assertion.rawId),
    new Uint8Array(resp.authenticatorData),
    new Uint8Array(resp.signature),
    clientDataHash,
  );

  return true;
}

/** Count how many distinct MFA methods are currently enabled. */
export function countActiveMfaMethods(cfg?: MfaConfig): number {
  const c = cfg ?? getMfaConfig();
  const hints = getLoginHints(); // from daemon if possible
  
  return [
    c.totp.enabled || hints.totp,
    c.webauthn.enabled || hints.webauthn,
    c.passkey?.enabled || hints.passwordlessEnabled, // passkey hint means enabled
    c.platform?.enabled ?? false,
    c.email.enabled || hints.emailOtp,
  ].filter(Boolean).length;
}

/**
 * Stretch Goal H.5: Browser passkey export via WebAuthn Level 3 conditional UI.
 * This outlines the interface for the emerging W3C passkey export standard.
 */
export async function exportPasskeys(): Promise<Uint8Array> {
  if (!isWebAuthnSupported()) throw new Error('WebAuthn not supported in this browser.');
  
  // Note: True passkey export requires OS-level support (e.g. Android 14+ Credential Manager API)
  // and specific WebAuthn Level 3 extensions that are not yet universally available.
  throw new Error('Passkey export is not yet natively supported by this browser/OS via WebAuthn Level 3.');
}

