/**
 * P2W - PWDnow proprietary vault export format
 *
 * Two cipher suites coexist in this module:
 *
 *   suite 0x01 (legacy v1, IMPORT-ONLY):
 *     KDF      : PBKDF2-SHA-512, 600 000 iterations
 *     Inner    : AES-256-GCM            (no AAD)
 *     Outer    : XChaCha20-Poly1305     (no AAD)
 *     MAC      : HMAC-SHA-512 × 2       (header + file)
 *
 *   suite 0x02 (current default, EXPORT + IMPORT):
 *     KDF      : Argon2id (RFC 9106), m = 256 MiB, t = 3, p = 1
 *     Subkeys  : HKDF-SHA3-512 with domain-separation labels
 *     Inner    : AES-256-GCM            (header bound as AAD)
 *     Outer    : XChaCha20-Poly1305     (header bound as AAD)
 *     MAC      : HMAC-SHA3-512 × 2      (header + file, defence-in-depth)
 *
 * The 2-byte "NZ" stub (0x6E 0x7A) is preserved across all suites and is the
 * very first thing in every .p2w file, analogous to the "MZ" header on PE
 * executables. See P2W_FORMAT.md for the full wire-format specification.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import type { Credential, Folder } from '../types';
import { generateUUID } from './crypto';

// ── Magic constants ────────────────────────────────────────────────────────────

/**
 * 2-byte DOS-style file signature prepended to every .p2w file (0x6E 0x7A =
 * ASCII "nz"). Visible as "nz" in any hex editor or forensic tool, analogous
 * to the "MZ" (0x4D 0x5A) signature on Windows PE executables.
 */
export const NZ_STUB      = new Uint8Array([0x6E, 0x7A]);
const        NZ_STUB_SIZE = 2;

export const P2W_MAGIC = new Uint8Array([0x50, 0x32, 0x57, 0x01]);
const PRF_MAGIC        = new Uint8Array([0xB7, 0xA2, 0x4F, 0x03]);
const FORMAT_VERSION   = 0x01;

const CIPHER_SUITE_V1 = 0x01;
const CIPHER_SUITE_V2 = 0x02;
const CIPHER_SUITE_V3 = 0x03;

// ── KDF parameter bounds (sanity checks on import) ────────────────────────────

/** v1 PBKDF2 lower bound - anything below this is rejected. */
const PBKDF2_MIN_ITERS = 100_000;
/** v1 PBKDF2 upper bound - anything above this is rejected (DoS prevention). */
const PBKDF2_MAX_ITERS = 2_000_000; // Lowered from 5M to reduce DoS window

/** v2 Argon2id memory cost (log2 of KiB). 12..18 → 4 MiB..256 MiB. */
const ARGON2_MIN_LOG2_M = 12;
const ARGON2_MAX_LOG2_M = 18; // F-01: Lowered from 19 (512MB) to 18 (256MB) to reduce DoS amplification
const ARGON2_MIN_T      = 1;
const ARGON2_MAX_T      = 3;  // F-01: Lowered from 5 to 3 to reduce DoS window
const ARGON2_MIN_P      = 1;
const ARGON2_MAX_P      = 4;

/** Defaults used by exportToP2W (suite 0x02). 18 = 256 MiB, t=1, p=1. */
const ARGON2_DEFAULT_LOG2_M = 18;
const ARGON2_DEFAULT_T      = 1; // F-06: Lower default t to improve defender experience while keeping cost high
const ARGON2_DEFAULT_P      = 1;

/** 
 * Payload padding configuration.
 * Padding is added to the plaintext PRF payload before encryption to mask 
 * the exact number of credentials and their field lengths (F-02).
 */
const MIN_PADDING_BYTES  = 128;   // Minimum noise

// F-02: Use exponential buckets to mask size more effectively
function getPaddingTarget(currentLen: number): number {
  const len = currentLen + MIN_PADDING_BYTES;
  if (len <= 65536) return 65536;    // 64 KB
  if (len <= 262144) return 262144;  // 256 KB
  if (len <= 1048576) return 1048576; // 1 MB
  // Above 1MB, pad to next 1MB boundary with randomized jitter
  const mb = 1048576;
  return Math.ceil(len / mb) * mb;
}

// ── Header field offsets (relative to start of header, file offset = +2) ─────

const HDR_MAGIC    = 0;   // 4 B
const HDR_VERSION  = 4;   // 1 B
const HDR_SUITE    = 5;   // 1 B
const HDR_FLAGS    = 6;   // 2 B
const HDR_CREATED  = 8;   // 8 B   (v1: ms epoch · v2: zeros)
const HDR_NCREDS   = 16;  // 4 B   (v1: count    · v2: zero)
const HDR_NFOLDS   = 20;  // 4 B   (v1: count    · v2: zero)
const HDR_SALT     = 24;  // 32 B  KDF salt (both suites)
const HDR_KDF_PARM = 56;  // 4 B   (v1: PBKDF2 iters BE · v2: [log2(m), t, p, 0x00])
const HDR_XNONCE   = 60;  // 24 B  XChaCha nonce
const HDR_ANONCE   = 84;  // 12 B  AES-GCM nonce
const HDR_SIZE     = 96;

const HEADER_MAC_SIZE = 64;
const FILE_MAC_SIZE   = 64;
const PAYLOAD_LEN_SIZE = 4;

const FIXED_OVERHEAD =
  NZ_STUB_SIZE + HDR_SIZE + HEADER_MAC_SIZE + PAYLOAD_LEN_SIZE + FILE_MAC_SIZE;

// ── Record and field type tags (spec §8) ──────────────────────────────────────

const R_META    = 0x01;
const R_FOLDER  = 0x10;
const R_ENTRY   = 0x20;
const R_PADDING = 0xFE; // New: Padding record ( Finding 2 )
const R_END     = 0xFF;

const F_END = 0xFF;

// META fields
const FM_APP_NAME  = 0x01;
const FM_APP_VER   = 0x02;
const FM_TIMESTAMP = 0x03;
const FM_NCREDS    = 0x04;
const FM_NFOLDS    = 0x05;

// FOLDER fields
const FF_ID    = 0x01;
const FF_LABEL = 0x02;
const FF_DESC  = 0x03;

// ENTRY fields
const FE_ID     = 0x01;
const FE_SVC    = 0x02;
const FE_URL    = 0x03;
const FE_USER   = 0x04;
const FE_PASS   = 0x05;
const FE_NOTES  = 0x06;
const FE_OTP    = 0x07;
const FE_FOLID  = 0x08;
const FE_STATUS = 0x09;
const FE_TAGS   = 0x0A;
const FE_TYPE   = 0x0B;

export const FAIL_MSG = 'Wrong passphrase or file has been tampered with.';

// ── Buffer writer ──────────────────────────────────────────────────────────────

class BufWriter {
  private parts: Uint8Array[] = [];
  private _len = 0;

  u8(v: number): void  { this._append(new Uint8Array([v & 0xFF])); }
  u16(v: number): void { this._append(new Uint8Array([(v >> 8) & 0xFF, v & 0xFF])); }
  u32(v: number): void {
    this._append(new Uint8Array([
      (v >>> 24) & 0xFF, (v >>> 16) & 0xFF, (v >>> 8) & 0xFF, v & 0xFF,
    ]));
  }
  write(data: Uint8Array): void { this._append(data); }

  private _append(d: Uint8Array): void { this.parts.push(d); this._len += d.length; }

  get length(): number { return this._len; }

  toUint8Array(): Uint8Array {
    const out = new Uint8Array(this._len);
    let off = 0;
    for (const p of this.parts) { out.set(p, off); off += p.length; }
    return out;
  }
}

// ── Buffer reader (bounds-checked: MED-9 fix) ─────────────────────────────────

class BufReader {
  private pos = 0;
  constructor(private data: Uint8Array) {}

  remaining(): number { return this.data.length - this.pos; }

  u8(): number {
    if (this.remaining() < 1) throw new Error('P2W parser: read past end of buffer');
    return this.data[this.pos++];
  }
  u16(): number {
    if (this.remaining() < 2) throw new Error('P2W parser: read past end of buffer');
    const v = ((this.data[this.pos] << 8) | this.data[this.pos + 1]) >>> 0;
    this.pos += 2;
    return v;
  }
  u32(): number {
    if (this.remaining() < 4) throw new Error('P2W parser: read past end of buffer');
    const v = ((this.data[this.pos] << 24) | (this.data[this.pos + 1] << 16) |
               (this.data[this.pos + 2] << 8)  | this.data[this.pos + 3]) >>> 0;
    this.pos += 4;
    return v;
  }
  bytes(n: number): Uint8Array {
    if (n < 0 || n > this.remaining()) throw new Error('P2W parser: read past end of buffer');
    const r = this.data.slice(this.pos, this.pos + n);
    this.pos += n;
    return r;
  }
  str(n: number): string { return DEC.decode(this.bytes(n)); }
}

const ENC = new TextEncoder();
const DEC = new TextDecoder();

// ── TLV field encoding ─────────────────────────────────────────────────────────

function writeStrField(w: BufWriter, tag: number, s: string | undefined | null): void {
  if (!s) return;
  const d = ENC.encode(s);
  if (d.length > 0xFFFF) throw new Error(`P2W field 0x${tag.toString(16)} exceeds 64 KiB`);
  w.u8(tag); w.u16(d.length); w.write(d);
}

function writeU32Field(w: BufWriter, tag: number, v: number): void {
  w.u8(tag); w.u16(4);
  w.u8((v >>> 24) & 0xFF); w.u8((v >>> 16) & 0xFF); w.u8((v >>> 8) & 0xFF); w.u8(v & 0xFF);
}

function endFields(w: BufWriter): void { w.u8(F_END); w.u16(0); }

// ── TLV field decoding ─────────────────────────────────────────────────────────

function readFields(r: BufReader): Map<number, Uint8Array> {
  const m = new Map<number, Uint8Array>();
  while (r.remaining() >= 3) {
    const tag = r.u8();
    const len = r.u16();
    if (tag === F_END) break;
    if (len > r.remaining()) throw new Error('P2W parser: TLV field exceeds remaining record');
    m.set(tag, r.bytes(len));
  }
  return m;
}

function strF(fields: Map<number, Uint8Array>, tag: number): string {
  const v = fields.get(tag);
  return v ? DEC.decode(v) : '';
}

function u32F(fields: Map<number, Uint8Array>, tag: number): number {
  const v = fields.get(tag);
  if (!v || v.length < 4) return 0;
  return ((v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3]) >>> 0;
}

// ── Record encoding ────────────────────────────────────────────────────────────

function writeRecord(w: BufWriter, type: number, body: Uint8Array): void {
  w.u8(type); w.u32(body.length); w.write(body);
}

function encodeMeta(exportDate: Date, nCreds: number, nFolds: number): Uint8Array {
  const w = new BufWriter();
  writeStrField(w, FM_APP_NAME,  'PWDnow');
  writeStrField(w, FM_APP_VER,   '1');
  writeStrField(w, FM_TIMESTAMP, exportDate.toISOString());
  writeU32Field(w, FM_NCREDS,    nCreds);
  writeU32Field(w, FM_NFOLDS,    nFolds);
  endFields(w);
  return w.toUint8Array();
}

function encodeFolder(f: Folder): Uint8Array {
  const w = new BufWriter();
  writeStrField(w, FF_ID,    f.id);
  writeStrField(w, FF_LABEL, f.label);
  writeStrField(w, FF_DESC,  f.description);
  endFields(w);
  return w.toUint8Array();
}

function encodeEntry(c: Credential): Uint8Array {
  const w = new BufWriter();
  writeStrField(w, FE_ID,     String(c.id));
  writeStrField(w, FE_SVC,    c.service);
  writeStrField(w, FE_URL,    c.url);
  writeStrField(w, FE_USER,   c.username);
  writeStrField(w, FE_PASS,   c.password ?? '');
  writeStrField(w, FE_NOTES,  c.description);
  writeStrField(w, FE_OTP,    c.otpSecret);
  writeStrField(w, FE_FOLID,  c.folderId);
  writeStrField(w, FE_STATUS, c.status);
  // F-12: Use Unit Separator (0x1F) instead of comma to prevent data corruption
  if (c.tags?.length) writeStrField(w, FE_TAGS, c.tags.join('\x1f'));
  writeStrField(w, FE_TYPE,   c.credentialType);
  endFields(w);
  return w.toUint8Array();
}

// ── PRF payload builder/parser ─────────────────────────────────────────────────

function buildPayload(credentials: Credential[], folders: Folder[], exportDate: Date): Uint8Array {
  const w = new BufWriter();
  w.write(PRF_MAGIC);
  writeRecord(w, R_META, encodeMeta(exportDate, credentials.length, folders.length));
  for (const f of folders)     writeRecord(w, R_FOLDER, encodeFolder(f));
  for (const c of credentials) writeRecord(w, R_ENTRY,  encodeEntry(c));

  // F-02: Exponential Padding to mask vault size
  const currentLen = w.length + 5; // +5 for R_END record
  const targetLen  = getPaddingTarget(currentLen);
  const paddingLen = targetLen - currentLen;

  if (paddingLen > 5) {
    const bodyLen = paddingLen - 5;
    const body = crypto.getRandomValues(new Uint8Array(bodyLen));
    writeRecord(w, R_PADDING, body);
  }

  w.u8(R_END); w.u32(0);
  return w.toUint8Array();
}

function parsePayload(data: Uint8Array): { credentials: Credential[]; folders: Folder[] } {
  const r = new BufReader(data);

  if (r.remaining() < 4) throw new Error(FAIL_MSG);
  const magic = r.bytes(4);
  if (!PRF_MAGIC.every((b, i) => b === magic[i])) throw new Error(FAIL_MSG);

  const credentials: Credential[] = [];
  const folders:     Folder[]     = [];
  let metaCreds = -1;
  let metaFolds = -1;

  // F-03 / F-16: Strict state machine for record order
  // 0: START, 1: META, 2: FOLDERS, 3: ENTRIES, 4: PADDING, 5: END
  let state = 0;

  while (r.remaining() > 0) {
    if (r.remaining() < 5) throw new Error(FAIL_MSG);
    const rtype = r.u8();
    const rlen  = r.u32();

    // F-10: Cap record length to remaining data
    if (rlen > r.remaining()) throw new Error(FAIL_MSG);
    const body = r.bytes(rlen);

    if (rtype === R_END) {
      if (state < 1) throw new Error(FAIL_MSG); // R_END before R_META
      state = 5;
      if (r.remaining() > 0) throw new Error(FAIL_MSG); // Data after R_END
      break;
    }

    if (rtype === R_PADDING) {
      if (state < 1) throw new Error(FAIL_MSG);
      state = 4;
      continue;
    }

    const bodyReader = new BufReader(body);
    const fields = readFields(bodyReader);
    // F-17: Ensure all bytes in record body were consumed by TLV parser
    if (bodyReader.remaining() > 0) throw new Error(FAIL_MSG);

    if (rtype === R_META) {
      if (state !== 0) throw new Error(FAIL_MSG); // Duplicate or out-of-order META
      metaCreds = u32F(fields, FM_NCREDS);
      metaFolds = u32F(fields, FM_NFOLDS);
      // F-04: Prevent memory DoS via unreasonable counts
      if (metaCreds > 50000 || metaFolds > 5000) throw new Error(FAIL_MSG);
      state = 1;
    } else if (rtype === R_FOLDER) {
      if (state > 2) throw new Error(FAIL_MSG); // Folders must come before entries/padding
      state = 2;

      const id = strF(fields, FF_ID);
      // F-15: ID validation
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id)) throw new Error(FAIL_MSG);

      folders.push({
        id,
        label:       strF(fields, FF_LABEL).slice(0, 256),
        description: strF(fields, FF_DESC).slice(0, 1024) || undefined,
      });
      if (folders.length > 5000) throw new Error(FAIL_MSG);
    } else if (rtype === R_ENTRY) {
      if (state > 3) throw new Error(FAIL_MSG); // Entries must come before padding
      state = 3;

      const id = strF(fields, FE_ID);
      if (id && !/^[a-zA-Z0-9_-]{1,64}$/.test(id)) throw new Error(FAIL_MSG);

      const tagStr = strF(fields, FE_TAGS);
      // F-12: Support Unit Separator (new) and comma (legacy)
      const tags = tagStr ? (tagStr.includes('\x1f') ? tagStr.split('\x1f') : tagStr.split(',')) : [];

      const rawType = strF(fields, FE_TYPE);
      // F-05: Validation of union types to prevent downstream injection
      const validTypes = ['login', 'passkey', 'secure_note', 'payment_card'];
      const credentialType = validTypes.includes(rawType) ? (rawType as Credential['credentialType']) : undefined;

      credentials.push({
        id:             id || generateUUID(),
        service:        strF(fields, FE_SVC).slice(0, 256),
        url:            strF(fields, FE_URL).slice(0, 2048),
        username:       strF(fields, FE_USER).slice(0, 256),
        password:       strF(fields, FE_PASS).slice(0, 4096),
        description:    strF(fields, FE_NOTES).slice(0, 10000) || undefined,
        otpSecret:      strF(fields, FE_OTP).slice(0, 256)     || undefined,
        folderId:       strF(fields, FE_FOLID).slice(0, 64),
        status:         strF(fields, FE_STATUS).slice(0, 32) || 'active',
        statusColor:    '#22c55e',
        logo:           '',
        tags:           tags.map(t => t.trim().slice(0, 64)).filter(Boolean),
        credentialType,
      } as Credential);

      if (credentials.length > 50000) throw new Error(FAIL_MSG);
    } else {
      // F-20: Unknown record types in a strict parser should fail
      throw new Error(FAIL_MSG);
    }
  }

  if (state < 1) throw new Error(FAIL_MSG); // No META record found

  if (metaCreds !== credentials.length || metaFolds !== folders.length) throw new Error(FAIL_MSG);

  return { credentials, folders };
}

// ── Key derivation ─────────────────────────────────────────────────────────────

interface DerivedKeys {
  K_xcha: Uint8Array; // 32 B - XChaCha20-Poly1305 outer layer
  K_aes:  Uint8Array; // 32 B - AES-256-GCM inner layer
  K_mac:  Uint8Array; // 32 B (v1) / 64 B (v2) - HMAC authentication
}

/** v1 PBKDF2-SHA-512 → byte-sliced subkeys (legacy import path). */
async function deriveKeysV1(passphrase: string, salt: Uint8Array, iters: number): Promise<DerivedKeys> {
  const utf8 = ENC.encode(passphrase.normalize('NFC'));            // MED-8: NFC normalise
  const mat = await crypto.subtle.importKey(
    'raw', utf8, 'PBKDF2', false, ['deriveBits'],
  );
  const raw = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-512', salt, iterations: iters },
      mat, 768,
    ),
  );
  return { K_xcha: raw.slice(0, 32), K_aes: raw.slice(32, 64), K_mac: raw.slice(64, 96) };
}

/** v2 Argon2id → HKDF-SHA3-512 with domain-separation labels. */
async function deriveKeysV2(
  passphrase: string,
  salt:       Uint8Array,
  log2M:      number,
  t:          number,
  p:          number,
): Promise<{ master: Uint8Array } & DerivedKeys> {
  const utf8 = ENC.encode(passphrase.normalize('NFC'));            // MED-8: NFC normalise
  const m = 1 << log2M; // KiB
  const master = await argon2idAsync(utf8, salt, {
    m, t, p, dkLen: 64,
    // Allow up to 1.25 GiB of working memory so m=1 GiB is reachable.
    maxmem: 1.25 * 1024 * 1024 * 1024,
  });
  // F-18: Use conformant HKDF (Extract then Expand) to address RFC 5869 compliance
  const K_aes  = hkdf(sha3_512, master, salt, ENC.encode('p2w/v2/aes-256-gcm'),       32);
  const K_xcha = hkdf(sha3_512, master, salt, ENC.encode('p2w/v2/xchacha20-poly'),    32);
  const K_mac  = hkdf(sha3_512, master, salt, ENC.encode('p2w/v2/hmac-sha3-512-mac'), 64);
  return { master, K_xcha, K_aes, K_mac };
}

// ── HMAC helpers (v1 = SHA-512, v2 = SHA3-512) ────────────────────────────────

function macV1(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha512, key, data);
}
function macV2(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha3_512, key, data);
}

function timingSafeEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * F-19: Best-effort buffer zeroisation.
 * Note: JS engines may have already copied the data elsewhere in memory (GC, slice, etc.).
 * This only zeroes the current backing store.
 */
function zeroise(...arrs: Uint8Array[]): void {
  for (const a of arrs) a.fill(0);
}

// ── Double AEAD encrypt/decrypt ────────────────────────────────────────────────

async function doubleEncrypt(
  plaintext: Uint8Array,
  K_aes:  Uint8Array, aesNonce:  Uint8Array,
  K_xcha: Uint8Array, xchaNonce: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const aesParams: AesGcmParams = aad
    ? { name: 'AES-GCM', iv: aesNonce, additionalData: aad }
    : { name: 'AES-GCM', iv: aesNonce };
  const aesKey  = await crypto.subtle.importKey('raw', K_aes, { name: 'AES-GCM' }, false, ['encrypt']);
  const innerCt = new Uint8Array(await crypto.subtle.encrypt(aesParams, aesKey, plaintext));
  return xchacha20poly1305(K_xcha, xchaNonce, aad).encrypt(innerCt);
}

async function doubleDecrypt(
  ciphertext: Uint8Array,
  K_aes:  Uint8Array, aesNonce:  Uint8Array,
  K_xcha: Uint8Array, xchaNonce: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const innerCt = xchacha20poly1305(K_xcha, xchaNonce, aad).decrypt(ciphertext);
  const aesParams: AesGcmParams = aad
    ? { name: 'AES-GCM', iv: aesNonce, additionalData: aad }
    : { name: 'AES-GCM', iv: aesNonce };
  const aesKey  = await crypto.subtle.importKey('raw', K_aes, { name: 'AES-GCM' }, false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt(aesParams, aesKey, innerCt));
}

// ── Public API: detection ─────────────────────────────────────────────────────

/**
 * Returns true when the file begins with the NZ stub followed by the P2W
 * magic word (regardless of cipher suite). In a hex editor the first two
 * bytes read "nz" (0x6E 0x7A), analogous to the "MZ" marker on Windows PE
 * files.
 */
export function isP2WFile(data: Uint8Array): boolean {
  return data.length >= NZ_STUB_SIZE + HDR_SIZE &&
    NZ_STUB.every((b, i) => data[i] === b) &&
    P2W_MAGIC.every((b, i) => data[NZ_STUB_SIZE + i] === b);
}

// ── Public API: export (always writes suite 0x02) ─────────────────────────────

/**
 * Optional knobs for `exportToP2W`. Production callers should omit this
 * argument so the strong defaults are used. Tests may supply minimum-bound
 * parameters to keep CI fast.
 */
export interface P2WExportOptions {
  kdfParams?: { log2M: number; t: number; p: number };
}

/**
 * Serialise credentials and folders into an encrypted, integrity-protected
 * `.p2w` binary blob using cipher suite 0x02 (Argon2id + HKDF-SHA3-512 +
 * AAD-bound double AEAD + HMAC-SHA3-512).
 *
 * The export instant and credential/folder counts are NOT placed in the
 * plaintext header (privacy fix HIGH-7); they live only inside the encrypted
 * PRF payload.
 */
export async function exportToP2W(
  credentials: Credential[],
  folders:     Folder[],
  passphrase:  string,
  options?:    P2WExportOptions,
): Promise<Uint8Array> {
  const salt      = crypto.getRandomValues(new Uint8Array(32));
  const xchaNonce = crypto.getRandomValues(new Uint8Array(24));
  const aesNonce  = crypto.getRandomValues(new Uint8Array(12));
  const log2M = options?.kdfParams?.log2M ?? ARGON2_DEFAULT_LOG2_M;
  const t     = options?.kdfParams?.t     ?? ARGON2_DEFAULT_T;
  const p     = options?.kdfParams?.p     ?? ARGON2_DEFAULT_P;
  if (log2M < ARGON2_MIN_LOG2_M || log2M > ARGON2_MAX_LOG2_M ||
      t     < ARGON2_MIN_T      || t     > ARGON2_MAX_T      ||
      p     < ARGON2_MIN_P      || p     > ARGON2_MAX_P)
    throw new Error('P2W: invalid Argon2id parameters');

  const keys = await deriveKeysV2(passphrase, salt, log2M, t, p);
  try {
    // 96-byte plaintext header. v2 leaves CREATED/CRED_COUNT/FOLD_COUNT zero.
    const header = new Uint8Array(HDR_SIZE);
    const dv     = new DataView(header.buffer);
    header.set(P2W_MAGIC, HDR_MAGIC);
    header[HDR_VERSION] = FORMAT_VERSION;
    header[HDR_SUITE]   = CIPHER_SUITE_V2;
    dv.setUint16(HDR_FLAGS, 0, false);
    // HDR_CREATED, HDR_NCREDS, HDR_NFOLDS stay zero by construction (v2 privacy).
    header.set(salt, HDR_SALT);
    header[HDR_KDF_PARM]     = log2M & 0xFF;
    header[HDR_KDF_PARM + 1] = t     & 0xFF;
    header[HDR_KDF_PARM + 2] = p     & 0xFF;
    header[HDR_KDF_PARM + 3] = 0x00;
    header.set(xchaNonce, HDR_XNONCE);
    header.set(aesNonce,  HDR_ANONCE);

    const payload    = buildPayload(credentials, folders, new Date());
    const ciphertext = await doubleEncrypt(
      payload, keys.K_aes, aesNonce, keys.K_xcha, xchaNonce,
      header, // HIGH-5: bind the header into both AEAD tags as AAD
    );

    const headerMac = macV2(keys.K_mac, header);

    const plenBytes = new Uint8Array(4);
    new DataView(plenBytes.buffer).setUint32(0, ciphertext.length, false);

    const bodyLen = NZ_STUB_SIZE + HDR_SIZE + HEADER_MAC_SIZE + PAYLOAD_LEN_SIZE + ciphertext.length;
    const body    = new Uint8Array(bodyLen);
    let off = 0;
    body.set(NZ_STUB,    off); off += NZ_STUB_SIZE;
    body.set(header,     off); off += HDR_SIZE;
    body.set(headerMac,  off); off += HEADER_MAC_SIZE;
    body.set(plenBytes,  off); off += PAYLOAD_LEN_SIZE;
    body.set(ciphertext, off);

    const fileMac = macV2(keys.K_mac, body);

    const file = new Uint8Array(bodyLen + FILE_MAC_SIZE);
    file.set(body,    0);
    file.set(fileMac, bodyLen);
    return file;
  } finally {
    zeroise(keys.master, keys.K_aes, keys.K_xcha, keys.K_mac);
  }
}

// ── Public API: import (auto-dispatches by suite byte) ────────────────────────

/**
 * Verify integrity and decrypt a `.p2w` file.
 *
 * Reads the cipher_suite byte and dispatches:
 *   - 0x01 → legacy v1 path (PBKDF2 + double AEAD without AAD)
 *   - 0x02 → current  v2 path (Argon2id + HKDF + AAD-bound double AEAD)
 *   - else → generic FAIL
 *
 * All post-magic failures collapse to one error string to avoid oracle
 * differentials across the (passphrase | tampering | downgrade) failure axes.
 */
export async function importFromP2W(
  data:       Uint8Array,
  passphrase: string,
): Promise<{ credentials: Credential[]; folders: Folder[] }> {
  if (!isP2WFile(data))
    throw new Error('Not a valid .p2w file.');
  if (data.length < FIXED_OVERHEAD)
    throw new Error('File is truncated or corrupted.');

  const NZ      = NZ_STUB_SIZE;
  const version = data[NZ + HDR_VERSION];
  if (version !== FORMAT_VERSION) throw new Error(FAIL_MSG);

  const suite = data[NZ + HDR_SUITE];
  if (suite === CIPHER_SUITE_V1) return importV1(data);
  if (suite === CIPHER_SUITE_V2) return importV2(data);
  // F-24: Generic error message for unsupported suites to prevent fingerprinting
  throw new Error(FAIL_MSG);

  async function importV1(file: Uint8Array): Promise<{ credentials: Credential[]; folders: Folder[] }> {
    const dv = new DataView(file.buffer, file.byteOffset, file.byteLength);
    const salt      = file.slice(NZ + HDR_SALT,   NZ + HDR_SALT   + 32);
    const iters     = dv.getUint32(NZ + HDR_KDF_PARM, false);
    const xchaNonce = file.slice(NZ + HDR_XNONCE,  NZ + HDR_XNONCE + 24);
    const aesNonce  = file.slice(NZ + HDR_ANONCE,  NZ + HDR_ANONCE + 12);

    if (iters < PBKDF2_MIN_ITERS || iters > PBKDF2_MAX_ITERS) throw new Error(FAIL_MSG);

    const payloadLen = dv.getUint32(NZ + HDR_SIZE + HEADER_MAC_SIZE, false);
    if (NZ + HDR_SIZE + HEADER_MAC_SIZE + PAYLOAD_LEN_SIZE + payloadLen + FILE_MAC_SIZE !== file.length)
      throw new Error(FAIL_MSG);

    const keys = await deriveKeysV1(passphrase, salt, iters);
    let plaintext: Uint8Array | null = null;
    try {
      const bodyEnd = file.length - FILE_MAC_SIZE;

      if (!timingSafeEq(macV1(keys.K_mac, file.slice(0, bodyEnd)), file.slice(bodyEnd)))
        throw new Error(FAIL_MSG);

      if (!timingSafeEq(
        macV1(keys.K_mac, file.slice(NZ, NZ + HDR_SIZE)),
        file.slice(NZ + HDR_SIZE, NZ + HDR_SIZE + HEADER_MAC_SIZE),
      )) throw new Error(FAIL_MSG);

      const ciphertext = file.slice(
        NZ + HDR_SIZE + HEADER_MAC_SIZE + PAYLOAD_LEN_SIZE,
        NZ + HDR_SIZE + HEADER_MAC_SIZE + PAYLOAD_LEN_SIZE + payloadLen,
      );

      try {
        plaintext = await doubleDecrypt(ciphertext, keys.K_aes, aesNonce, keys.K_xcha, xchaNonce);
      } catch {
        throw new Error(FAIL_MSG);
      }
      return parsePayload(plaintext);
    } finally {
      zeroise(keys.K_aes, keys.K_xcha, keys.K_mac);
      // F-08: Zeroise plaintext buffer after use
      if (plaintext) zeroise(plaintext);
    }
  }

  async function importV2(file: Uint8Array): Promise<{ credentials: Credential[]; folders: Folder[] }> {
    const dv = new DataView(file.buffer, file.byteOffset, file.byteLength);
    const salt      = file.slice(NZ + HDR_SALT,    NZ + HDR_SALT   + 32);
    const log2M     = file[NZ + HDR_KDF_PARM];
    const t         = file[NZ + HDR_KDF_PARM + 1];
    const p         = file[NZ + HDR_KDF_PARM + 2];
    const xchaNonce = file.slice(NZ + HDR_XNONCE,  NZ + HDR_XNONCE + 24);
    const aesNonce  = file.slice(NZ + HDR_ANONCE,  NZ + HDR_ANONCE + 12);

    // F-22: Assert that reserved header fields (flags, created_at) are zero in v2
    const flags = dv.getUint16(NZ + HDR_FLAGS, false);
    const hiCreated = dv.getUint32(NZ + HDR_CREATED, false);
    const loCreated = dv.getUint32(NZ + HDR_CREATED + 4, false);
    if (flags !== 0 || hiCreated !== 0 || loCreated !== 0) throw new Error(FAIL_MSG);

    if (log2M < ARGON2_MIN_LOG2_M || log2M > ARGON2_MAX_LOG2_M) throw new Error(FAIL_MSG);
    if (t     < ARGON2_MIN_T      || t     > ARGON2_MAX_T)     throw new Error(FAIL_MSG);
    if (p     < ARGON2_MIN_P      || p     > ARGON2_MAX_P)     throw new Error(FAIL_MSG);

    const payloadLen = dv.getUint32(NZ + HDR_SIZE + HEADER_MAC_SIZE, false);
    if (NZ + HDR_SIZE + HEADER_MAC_SIZE + PAYLOAD_LEN_SIZE + payloadLen + FILE_MAC_SIZE !== file.length)
      throw new Error(FAIL_MSG);

    const keys = await deriveKeysV2(passphrase, salt, log2M, t, p);
    let plaintext: Uint8Array | null = null;
    try {
      const bodyEnd = file.length - FILE_MAC_SIZE;
      const header  = file.slice(NZ, NZ + HDR_SIZE);

      if (!timingSafeEq(macV2(keys.K_mac, file.slice(0, bodyEnd)), file.slice(bodyEnd)))
        throw new Error(FAIL_MSG);

      if (!timingSafeEq(
        macV2(keys.K_mac, header),
        file.slice(NZ + HDR_SIZE, NZ + HDR_SIZE + HEADER_MAC_SIZE),
      )) throw new Error(FAIL_MSG);

      const ciphertext = file.slice(
        NZ + HDR_SIZE + HEADER_MAC_SIZE + PAYLOAD_LEN_SIZE,
        NZ + HDR_SIZE + HEADER_MAC_SIZE + PAYLOAD_LEN_SIZE + payloadLen,
      );

      try {
        plaintext = await doubleDecrypt(
          ciphertext, keys.K_aes, aesNonce, keys.K_xcha, xchaNonce, header,
        );
      } catch {
        throw new Error(FAIL_MSG);
      }
      return parsePayload(plaintext);
    } finally {
      zeroise(keys.master, keys.K_aes, keys.K_xcha, keys.K_mac);
      // F-08: Zeroise plaintext buffer after use
      if (plaintext) zeroise(plaintext);
    }
  }
}

/**
 * Export timestamp embedded in the legacy v1 plaintext header (ms since
 * epoch). v2 files no longer carry the timestamp in the clear - the export
 * instant lives inside the encrypted PRF payload, accessible only after
 * successful decryption. Returns null for v2 or non-P2W data.
 */
export function readP2WTimestamp(data: Uint8Array): Date | null {
  if (!isP2WFile(data)) return null;
  const suite = data[NZ_STUB_SIZE + HDR_SUITE];
  if (suite !== CIPHER_SUITE_V1) return null;
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const hi = dv.getUint32(NZ_STUB_SIZE + HDR_CREATED,     false);
  const lo = dv.getUint32(NZ_STUB_SIZE + HDR_CREATED + 4, false);
  return new Date(hi * 0x100000000 + lo);
}

/** Cipher suite byte from the header. Returns null for non-P2W data. */
export function readP2WCipherSuite(data: Uint8Array): number | null {
  if (!isP2WFile(data)) return null;
  return data[NZ_STUB_SIZE + HDR_SUITE];
}
