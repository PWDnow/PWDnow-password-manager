/** @vitest-environment jsdom */
/**
 * Regression: when v2 (Argon2id WASM) cannot derive — e.g. CSP blocks
 * WebAssembly.compile because 'wasm-unsafe-eval' is missing — v1 (PBKDF2)
 * MUST still be returned. Otherwise the user logs in but every encrypted
 * read/write silently no-ops, folders disappear, and creation fails.
 *
 * See LOGIN_PERFORMANCE_PLAN.md and the 2026-05-08 bug report.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock the WASM Argon2id helper to throw exactly like a CSP block would.
vi.mock('./argon2', () => ({
  argon2idWasm: vi.fn().mockRejectedValue(
    new Error("WebAssembly.compile() blocked by Content Security Policy"),
  ),
}));

import { deriveLocalKeys } from './keystore';

describe('deriveLocalKeys resilience', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('returns v1 keys even when v2 (WASM Argon2id) is blocked', async () => {
    const result = await deriveLocalKeys(
      'TestPassword!',
      '0123456789abcdef0123456789abcdef',
      'session-token-123',
    );
    expect(result.v1).toBeTruthy();
    expect(result.v1.encKey).toBeInstanceOf(CryptoKey);
    expect(result.v1.sigKey).toBeInstanceOf(CryptoKey);
    // v2 must be null (not undefined, not throwing) so callers can branch on it.
    expect(result.v2).toBeNull();
  }, 30_000);

  it('still returns v1 keys when no token is provided (v2 skipped entirely)', async () => {
    const result = await deriveLocalKeys(
      'TestPassword!',
      '0123456789abcdef0123456789abcdef',
    );
    expect(result.v1.encKey).toBeInstanceOf(CryptoKey);
    expect(result.v2).toBeNull();
  }, 30_000);
});
