/**
 * Argon2id wrapper backed by hash-wasm (WebAssembly + SIMD where supported).
 *
 * Replaces the pure-JS `@noble/hashes/argon2.js` implementation that used to
 * run on the main thread inside `deriveLocalKeys`. Same NIST PQC L5 parameters
 * (256 MiB / t=4 / p=1) — only the implementation changes. See
 * LOGIN_PERFORMANCE_PLAN.md for context.
 */
import { argon2id as wasmArgon2id } from 'hash-wasm';

export interface Argon2idParams {
  /** Iteration count (Argon2 t). */
  t: number;
  /** Memory in kibibytes (Argon2 m). */
  m: number;
  /** Parallelism (Argon2 p). */
  p: number;
  /** Output length in bytes. */
  dkLen: number;
}

/**
 * Drop-in replacement for the @noble/hashes argon2id signature we used before.
 * Returns the raw derived bytes — the caller is responsible for HKDF / key
 * import. `password` and `salt` are NOT zeroized here; the caller owns lifetime.
 */
export async function argon2idWasm(
  password: Uint8Array,
  salt: Uint8Array,
  { t, m, p, dkLen }: Argon2idParams,
): Promise<Uint8Array> {
  return wasmArgon2id({
    password,
    salt,
    iterations: t,
    parallelism: p,
    memorySize: m,
    hashLength: dkLen,
    outputType: 'binary',
  });
}
