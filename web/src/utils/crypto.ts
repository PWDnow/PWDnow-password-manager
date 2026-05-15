/**
 * Password hashing for the localStorage demo-mode fallback.
 *
 * HIGH-02 / MED-01 fix: generate a cryptographically random 16-byte salt per
 * user (stored alongside the hash) instead of using the email as a predictable
 * salt.  Iterations bumped to 310 000 (OWASP 2023 minimum for PBKDF2-SHA-256).
 *
 * Primary path: the daemon uses Argon2id (256 MiB / t=3 / p=4) - this code
 * is ONLY reached when the daemon is unavailable (offline demo mode).
 *
 * Secure context (HTTPS / localhost): uses WebCrypto subtle API.
 * Non-secure context fallback: uses @noble/hashes PBKDF2 so the app
 * still functions over plain HTTP during development.
 */
// PBKDF2-HMAC-SHA-512, 1,000,000 iterations — NSA CNSA 2.0 (CSI-CNSA-2.0, Sept 2022); salt per NIST SP 800-132 (2010).
// Noble sha512 used as fallback when WebCrypto is unavailable (plain HTTP dev).
// sha256 retained only for hashEmail (lookup, not key establishment — CNSA 2.0 allows this).
import { pbkdf2 as noblePbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha512 as nobleSha512, sha256 as nobleSha256 } from '@noble/hashes/sha2.js';

const PBKDF2_ITERATIONS = 1_000_000;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * One-way hash of an email address for localStorage lookup.
 * SHA-256 of the lowercased, trimmed email - never stored in plaintext.
 * Works on plain HTTP (noble) and HTTPS (WebCrypto).
 */
export async function hashEmail(email: string): Promise<string> {
  const normalized = new TextEncoder().encode(email.trim().toLowerCase());
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const buf = await crypto.subtle.digest('SHA-256', normalized);
    return bytesToHex(new Uint8Array(buf));
  }
  return bytesToHex(nobleSha256(normalized));
}

/** Generate a random 16-byte hex salt for a new user registration. */
export function generateSalt(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * Hash a password for demo-mode localStorage storage.
 * @param password  The plaintext password.
 * @param saltHex   Hex-encoded 16-byte random salt (from generateSalt()).
 *                  Legacy callers may pass an email string; we handle both.
 */
export async function hashPassword(password: string, saltHex = ''): Promise<string> {
  const enc = new TextEncoder();
  const passwordBytes = enc.encode(password);
  // Support both new hex-salt format (32 hex chars = 16 bytes) and legacy email salt
  const saltBytes = /^[0-9a-f]{32}$/i.test(saltHex)
    ? hexToBytes(saltHex)
    : enc.encode(saltHex || 'pwdnow-demo-salt');

  if (typeof crypto !== 'undefined' && crypto.subtle) {
    // Secure context: use WebCrypto PBKDF2
    const keyMaterial = await crypto.subtle.importKey(
      'raw', passwordBytes, 'PBKDF2', false, ['deriveBits'],
    );
    // CNSA 2.0: SHA-512, 64-byte output truncated to hex (first 32 bytes used as hash).
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-512', salt: saltBytes, iterations: PBKDF2_ITERATIONS },
      keyMaterial,
      256,
    );
    return bytesToHex(new Uint8Array(bits));
  }

  // Non-secure context fallback (@noble/hashes) - plain HTTP dev only.
  return bytesToHex(noblePbkdf2(nobleSha512, passwordBytes, saltBytes, { c: PBKDF2_ITERATIONS, dkLen: 32 }));
}

/**
 * Compare two hex-encoded hash strings without short-circuiting.
 * JS engines don't guarantee constant-time, but XOR-over-all-bytes
 * eliminates the most obvious timing leak (early return on first mismatch).
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

/**
 * Generate a random 32-character recovery key.
 * Uses a safe character set to avoid ambiguous characters (O vs 0, I vs 1).
 */
export function generateRecoveryKey(): string {
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let result = '';
  for (let i = 0; i < 32; i++) {
    result += charset[bytes[i] % charset.length];
    if ((i + 1) % 8 === 0 && i < 31) result += '-';
  }
  return result;
}

/**
 * UUID v4 generator that works in both secure (HTTPS/localhost) and
 * non-secure (plain HTTP LAN) contexts.
 * HIGH-04 fix: use crypto.getRandomValues() instead of Math.random() fallback.
 * crypto.getRandomValues is available in all contexts (even non-secure HTTP).
 */
export function generateUUID(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  // RFC 4122 §4.4 compliant v4 UUID via crypto.getRandomValues (always available)
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant bits
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}
