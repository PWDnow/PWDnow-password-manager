/// <reference lib="webworker" />
/**
 * Off-main-thread KDF worker.
 *
 * Runs Argon2id (256 MiB / t=4 / p=1) inside a Web Worker so the password
 * form never freezes during login. The worker only computes the raw 64-byte
 * master output; the main thread does HKDF + WebCrypto key import (sub-ms).
 *
 * Wire format (matching `web/src/crypto/keystore.ts::deriveLocalKeys`):
 *
 *   in  → { id, password: Uint8Array, salt: Uint8Array, t, m, p, dkLen }
 *   out → { id, ok: true, master: Uint8Array }
 *      | { id, ok: false, error: string }
 */
import { argon2idWasm } from './argon2';

interface KdfRequest {
  id: number;
  password: Uint8Array;
  salt: Uint8Array;
  t: number;
  m: number;
  p: number;
  dkLen: number;
}

self.onmessage = async (ev: MessageEvent<KdfRequest>) => {
  const { id, password, salt, t, m, p, dkLen } = ev.data;
  try {
    const master = await argon2idWasm(password, salt, { t, m, p, dkLen });
    // Transferable ownership of the buffer back to the main thread — avoids
    // an extra copy of the 64-byte output.
    (self as unknown as Worker).postMessage(
      { id, ok: true, master },
      { transfer: [master.buffer] },
    );
  } catch (err) {
    (self as unknown as Worker).postMessage({
      id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    });
  }
};

export {}; // module worker
