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

import { TOTP } from 'totp-generator';
import { keyStore } from '../crypto/keystore';

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
  passwordlessEnabled?: boolean;  // when true, password field is hidden at login
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

function bytesToB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}
function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

/** Call once at login (after keyStore.storeLocalKey is called) to decrypt MFA config into memory. */
export async function loadMfaConfig(): Promise<void> {
  try {
    const raw = localStorage.getItem(MFA_KEY);
    if (!raw) { _mfaCache = DEFAULT_MFA(); return; }
    const parsed = JSON.parse(raw);

    if (parsed.enc === 1) {
      const key = keyStore.getLocalKey();
      if (!key) { _mfaCache = DEFAULT_MFA(); return; }
      const iv = b64ToBytes(parsed.iv);
      const ct = b64ToBytes(parsed.ct);
      const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      _mfaCache = JSON.parse(new TextDecoder().decode(plaintext)) as MfaConfig;
    } else {
      // Legacy plaintext — load into cache; will be re-encrypted on next save
      _mfaCache = parsed as MfaConfig;
    }
  } catch {
    _mfaCache = DEFAULT_MFA();
  }
}

/** Clear the in-memory cache on logout or tab close. */
export function clearMfaCache(): void {
  _mfaCache = null;
}

/** Synchronous read from in-memory cache. */
export function getMfaConfig(): MfaConfig {
  return _mfaCache ?? DEFAULT_MFA();
}

/** Update cache and persist encrypted ciphertext to localStorage. */
export function saveMfaConfig(cfg: MfaConfig): void {
  _mfaCache = cfg;
  const key = keyStore.getLocalKey();
  if (key) {
    // Async encrypt — fire and forget (the cache is already updated synchronously)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(cfg));
    crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext).then(ct => {
      localStorage.setItem(MFA_KEY, JSON.stringify({ enc: 1, iv: bytesToB64(iv), ct: bytesToB64(new Uint8Array(ct)) }));
    }).catch(() => { /* non-fatal: cache is authoritative */ });
  }
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
export function buildTotpUri(secret: string, accountEmail: string, issuer = 'PWDnow'): string {
  const label = encodeURIComponent(`${issuer}:${accountEmail}`);
  return (
    `otpauth://totp/${label}` +
    `?secret=${secret}` +
    `&issuer=${encodeURIComponent(issuer)}` +
    `&algorithm=SHA1` +
    `&digits=6` +
    `&period=30`
  );
}

// MED-04: in-memory set of recently consumed TOTP periods.
// Key: `${secret}:${period}` where period = Math.floor(timestamp / 30000).
// Value: expiry epoch (ms) after which the entry can be garbage-collected.
const _usedTotpPeriods = new Map<string, number>();

/**
 * Verify a 6-digit TOTP code against the stored secret.
 * Checks current period ± 1 step to tolerate ≤30 s clock drift.
 * MED-04: rejects codes that have already been used in the same period (replay).
 */
export async function verifyTotp(secret: string, token: string): Promise<boolean> {
  const clean = token.replace(/\s/g, '');
  if (!/^\d{6}$/.test(clean)) return false;
  const now = Date.now();

  // Garbage-collect expired entries
  for (const [key, expiry] of _usedTotpPeriods) {
    if (now > expiry) _usedTotpPeriods.delete(key);
  }

  for (const drift of [-30000, 0, 30000]) {
    const ts = now + drift;
    const { otp } = await TOTP.generate(secret, { timestamp: ts });
    if (otp === clean) {
      const period = Math.floor(ts / 30_000);
      const replayKey = `${secret}:${period}`;
      if (_usedTotpPeriods.has(replayKey)) return false; // replay detected
      // Mark this period as consumed; expire after 2 full periods (60 s safety margin)
      _usedTotpPeriods.set(replayKey, (period + 2) * 30_000);
      return true;
    }
  }
  return false;
}

// ─── Email OTP ─────────────────────────────────────────────────────────────────
// Code is held ONLY in module memory — never written to localStorage/sessionStorage.
// TTL is 5 minutes. This is a client-side simulation for the demo.

interface PendingEmailOtp {
  code: string;
  email: string;
  expires: number;
}

let _pendingOtp: PendingEmailOtp | null = null;

/** Generate a 6-digit OTP and return it (caller shows it in simulated email). */
export function generateEmailCode(email: string): string {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
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
 * WebAuthn Registration Ceremony (FIDO2 MakeCredential).
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

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userIdBytes = new TextEncoder().encode(userId);

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: {
        name: 'PWDnow',
        id: window.location.hostname,
      },
      user: {
        id: userIdBytes,
        name: email,
        displayName,
      },
      pubKeyCredParams: [
        { alg: -7,   type: 'public-key' }, // ES256  (ECDSA P-256)
        { alg: -257, type: 'public-key' }, // RS256  (RSA-PKCS1-v1_5)
        { alg: -37,  type: 'public-key' }, // PS256  (RSA-PSS)
      ],
      authenticatorSelection: {
        // 'cross-platform' = external keys (YubiKey, Titan); 'platform' = TPM/Touch ID
        authenticatorAttachment: 'cross-platform',
        userVerification: 'preferred',
        requireResidentKey: false,
        residentKey: 'preferred',
      },
      timeout: 60_000,
      attestation: 'none', // we don't need to verify manufacturer attestation
      extensions: { credProps: true },
    },
  }) as PublicKeyCredential;

  if (!credential) throw new Error('Registration cancelled.');

  const response = credential.response as AuthenticatorAttestationResponse;
  const credId = bufToB64url(credential.rawId);

  // Extract the public key bytes from the attestation object for future storage
  // (we store the raw credentialId; full CBOR parsing is server-side in real apps)
  const meta: WebAuthnCredentialMeta = {
    id:        credId,
    rawId:     credId,
    name:      credentialName,
    createdAt: Date.now(),
    counter:   0,
  };

  // Persist to mfa_config
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
    throw new Error('Signature counter decreased — possible cloned authenticator!');
  }
  stored.counter = newCounter;
  saveMfaConfig(cfg);

  return true;
}

// ─── Passkey / Platform Auth ──────────────────────────────────────────────────

/**
 * Non-sensitive hint stored in plaintext so the login page can show the
 * "Use Passkey" button and target the right credentials without decrypting
 * the full MFA config (which requires the password-derived local key).
 */
const PASSKEY_HINT_KEY = '_pwdn_pk_hint';

function savePasskeyHint(credentials: WebAuthnCredentialMeta[]): void {
  const ids = credentials.map(c => ({ id: c.rawId, name: c.name }));
  localStorage.setItem(PASSKEY_HINT_KEY, JSON.stringify(ids));
}

export function getPasskeyHint(): Array<{ id: string; name: string }> {
  try {
    const s = localStorage.getItem(PASSKEY_HINT_KEY);
    return s ? (JSON.parse(s) as Array<{ id: string; name: string }>) : [];
  } catch { return []; }
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

/** Count how many distinct MFA methods are currently enabled. */
export function countActiveMfaMethods(cfg?: MfaConfig): number {
  const c = cfg ?? getMfaConfig();
  return [
    c.totp.enabled,
    c.webauthn.enabled,
    c.passkey?.enabled ?? false,
    c.platform?.enabled ?? false,
    c.email.enabled,
  ].filter(Boolean).length;
}
