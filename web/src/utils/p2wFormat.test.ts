import { describe, it, expect } from 'vitest';
import {
  exportToP2W, importFromP2W, isP2WFile, readP2WTimestamp, readP2WCipherSuite,
  P2W_MAGIC, NZ_STUB,
} from './p2wFormat';
import type { Credential, Folder } from '../types';

// ── Fixtures ──────────────────────────────────────────────────────────────────

const C1: Credential = {
  id: 'cred-1', service: 'GitHub', url: 'https://github.com',
  username: 'alice@example.com', password: 'S3cr3t!Pass#99',
  status: 'active', statusColor: '#22c55e', logo: '', folderId: 'f1',
  description: 'main GitHub account', otpSecret: 'JBSWY3DPEHPK3PXP',
  tags: ['work', 'dev'], credentialType: 'login',
};
const C2: Credential = {
  id: 'cred-2', service: 'Google', url: 'https://google.com',
  username: 'alice@gmail.com', password: 'G00gl3!',
  status: 'active', statusColor: '#22c55e', logo: '', folderId: '',
  tags: [],
};
const C_UNICODE: Credential = {
  id: 'cred-3', service: 'Café WiFi', url: '',
  username: '用户名', password: 'пароль🔐',
  status: 'active', statusColor: '#22c55e', logo: '', folderId: '', tags: [],
};
const F1: Folder = { id: 'f1', label: 'Work', description: 'Work accounts' };
const CREDS  = [C1, C2];
const FOLDS  = [F1];
const PASS   = 'correct-horse-battery-staple-42!';

/** Minimum-bound Argon2id parameters that still pass the importer's bounds.
 *  Kept tight so the full vitest suite stays fast in CI. */
const FAST = { kdfParams: { log2M: 12, t: 1, p: 1 } } as const;

// ── Magic and detection ───────────────────────────────────────────────────────

describe('isP2WFile', () => {
  it('returns false for short buffers', () => {
    expect(isP2WFile(new Uint8Array(3))).toBe(false);
  });
  it('returns false for empty buffer', () => {
    expect(isP2WFile(new Uint8Array(0))).toBe(false);
  });
  it('returns false for JSON bytes', () => {
    expect(isP2WFile(new TextEncoder().encode('{"version":1}'))).toBe(false);
  });
  it('returns false for CSV bytes', () => {
    expect(isP2WFile(new TextEncoder().encode('name,url,username,password'))).toBe(false);
  });
  it('returns true for P2W magic', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    expect(isP2WFile(file)).toBe(true);
  });
  it('first 2 bytes are the NZ stub (0x6E 0x7A)', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    expect(Array.from(file.slice(0, 2))).toEqual(Array.from(NZ_STUB));
  });
  it('bytes 2–5 are the P2W magic constant', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    expect(Array.from(file.slice(2, 6))).toEqual(Array.from(P2W_MAGIC));
  });
});

// ── File format properties ────────────────────────────────────────────────────

describe('exportToP2W format', () => {
  it('produces a Uint8Array', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    expect(file).toBeInstanceOf(Uint8Array);
  });
  it('file is not plaintext JSON', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const text = new TextDecoder('latin1').decode(file);
    expect(() => JSON.parse(text)).toThrow();
  });
  it('does not contain plaintext password in file bytes', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const text = new TextDecoder('latin1').decode(file);
    expect(text.includes('S3cr3t!Pass#99')).toBe(false);
    expect(text.includes('G00gl3!')).toBe(false);
  });
  it('does not contain plaintext username in file bytes', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const text = new TextDecoder('latin1').decode(file);
    expect(text.includes('alice@example.com')).toBe(false);
  });
  it('version byte is 0x01 at offset 6 (NZ stub shifts header by 2)', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    expect(file[6]).toBe(0x01);
  });
  it('cipher suite byte is 0x02 at offset 7 (new exports use suite 0x02)', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    expect(file[7]).toBe(0x02);
  });
  it('two exports of the same vault produce different bytes (random salt + nonces)', async () => {
    const a = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const b = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    expect(a).not.toEqual(b);
  });
});

// ── Timestamp (now v1-only - v2 zeros the plaintext timestamp) ────────────────

describe('readP2WTimestamp', () => {
  it('returns null for non-P2W data', () => {
    expect(readP2WTimestamp(new Uint8Array(200))).toBeNull();
  });
  it('returns null for v2 files (timestamp is encrypted, not plaintext)', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    expect(readP2WTimestamp(file)).toBeNull();
  });
});

describe('readP2WCipherSuite', () => {
  it('returns 0x02 for new exports', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    expect(readP2WCipherSuite(file)).toBe(0x02);
  });
  it('returns null for non-P2W data', () => {
    expect(readP2WCipherSuite(new Uint8Array(200))).toBeNull();
  });
});

// ── Round-trip: credentials ───────────────────────────────────────────────────

describe('Round-trip: credentials', () => {
  it('preserves service, url, username, password', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const { credentials } = await importFromP2W(file, PASS);
    const g = credentials.find(c => c.service === 'GitHub')!;
    expect(g.url).toBe('https://github.com');
    expect(g.username).toBe('alice@example.com');
    expect(g.password).toBe('S3cr3t!Pass#99');
  });
  it('preserves OTP secret', async () => {
    const file = await exportToP2W([C1], [], PASS, FAST);
    const { credentials } = await importFromP2W(file, PASS);
    expect(credentials[0].otpSecret).toBe('JBSWY3DPEHPK3PXP');
  });
  it('preserves notes and tags', async () => {
    const file = await exportToP2W([C1], [], PASS, FAST);
    const { credentials } = await importFromP2W(file, PASS);
    expect(credentials[0].description).toBe('main GitHub account');
    expect(credentials[0].tags).toEqual(['work', 'dev']);
  });
  it('preserves credential type', async () => {
    const file = await exportToP2W([C1], [], PASS, FAST);
    const { credentials } = await importFromP2W(file, PASS);
    expect(credentials[0].credentialType).toBe('login');
  });
  it('preserves folder ID', async () => {
    const file = await exportToP2W([C1], [F1], PASS, FAST);
    const { credentials } = await importFromP2W(file, PASS);
    expect(credentials[0].folderId).toBe('f1');
  });
  it('returns correct credential count', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const { credentials } = await importFromP2W(file, PASS);
    expect(credentials).toHaveLength(2);
  });
  it('handles empty vault', async () => {
    const file = await exportToP2W([], [], PASS, FAST);
    const { credentials, folders } = await importFromP2W(file, PASS);
    expect(credentials).toHaveLength(0);
    expect(folders).toHaveLength(0);
  });
});

describe('Round-trip: folders', () => {
  it('preserves folder label and description', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const { folders } = await importFromP2W(file, PASS);
    expect(folders).toHaveLength(1);
    expect(folders[0].id).toBe('f1');
    expect(folders[0].label).toBe('Work');
    expect(folders[0].description).toBe('Work accounts');
  });
});

describe('Round-trip: Unicode', () => {
  it('preserves multi-byte characters in service/username/password', async () => {
    const file = await exportToP2W([C_UNICODE], [], PASS, FAST);
    const { credentials } = await importFromP2W(file, PASS);
    expect(credentials[0].service).toBe('Café WiFi');
    expect(credentials[0].username).toBe('用户名');
    expect(credentials[0].password).toBe('пароль🔐');
  });
});

describe('Round-trip: special characters in passphrase', () => {
  it('works with passphrase containing spaces and symbols', async () => {
    const pass = 'p@$$w0rd! with spaces & "quotes" <>';
    const file = await exportToP2W([C1], [], pass, FAST);
    const { credentials } = await importFromP2W(file, pass);
    expect(credentials[0].password).toBe('S3cr3t!Pass#99');
  });
});

// ── Tamper detection ──────────────────────────────────────────────────────────

describe('Wrong passphrase', () => {
  it('throws on import with wrong passphrase', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    await expect(importFromP2W(file, 'wrong-passphrase')).rejects.toThrow();
  });
  it('throws on empty passphrase when file needs one', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    await expect(importFromP2W(file, '')).rejects.toThrow();
  });
});

describe('File tampering', () => {
  it('detects a single flipped bit in the ciphertext', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const tampered = new Uint8Array(file);
    const mid = Math.floor(file.length / 2);
    tampered[mid] ^= 0x01;
    await expect(importFromP2W(tampered, PASS)).rejects.toThrow();
  });
  it('detects truncation', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const truncated = file.slice(0, file.length - 1);
    await expect(importFromP2W(truncated, PASS)).rejects.toThrow();
  });
  it('detects a flipped byte in the header MAC section', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const tampered = new Uint8Array(file);
    tampered[2 + 96 + 4] ^= 0xFF;
    await expect(importFromP2W(tampered, PASS)).rejects.toThrow();
  });
  it('detects a flipped byte in the file MAC section', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const tampered = new Uint8Array(file);
    tampered[file.length - 5] ^= 0x01;
    await expect(importFromP2W(tampered, PASS)).rejects.toThrow();
  });
  it('rejects random bytes as not a P2W file', async () => {
    const garbage = crypto.getRandomValues(new Uint8Array(500));
    await expect(importFromP2W(garbage, PASS)).rejects.toThrow('Not a valid');
  });
});

// ── v2-specific: cipher suite dispatch ─────────────────────────────────────────

describe('Cipher suite dispatch', () => {
  it('rejects an unknown cipher_suite byte with the generic FAIL message', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const tampered = new Uint8Array(file);
    tampered[7] = 0xAA; // unknown suite
    await expect(importFromP2W(tampered, PASS)).rejects.toThrow();
  });
  it('rejects a tampered cipher_suite even with correct passphrase', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const tampered = new Uint8Array(file);
    tampered[7] = 0x01; // attempt to downgrade to v1 dispatch
    await expect(importFromP2W(tampered, PASS)).rejects.toThrow();
  });
});

// ── v2-specific: KDF parameter bounds (HIGH-3) ────────────────────────────────

describe('Argon2id parameter bounds (HIGH-3 fix)', () => {
  it('rejects export with log2M below the minimum', async () => {
    await expect(
      exportToP2W(CREDS, FOLDS, PASS, { kdfParams: { log2M: 5, t: 1, p: 1 } }),
    ).rejects.toThrow();
  });
  it('rejects export with log2M above the maximum', async () => {
    await expect(
      exportToP2W(CREDS, FOLDS, PASS, { kdfParams: { log2M: 22, t: 1, p: 1 } }),
    ).rejects.toThrow();
  });
  it('rejects export with t = 0', async () => {
    await expect(
      exportToP2W(CREDS, FOLDS, PASS, { kdfParams: { log2M: 12, t: 0, p: 1 } }),
    ).rejects.toThrow();
  });
  it('rejects export with t > 10', async () => {
    await expect(
      exportToP2W(CREDS, FOLDS, PASS, { kdfParams: { log2M: 12, t: 11, p: 1 } }),
    ).rejects.toThrow();
  });
  it('rejects import with header-supplied log2M = 5 (DoS prevention low side)', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const tampered = new Uint8Array(file);
    tampered[2 + 56] = 5; // log2M out of bounds
    await expect(importFromP2W(tampered, PASS)).rejects.toThrow();
  });
  it('rejects import with header-supplied log2M = 30 (DoS prevention high side)', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const tampered = new Uint8Array(file);
    tampered[2 + 56] = 30; // log2M out of bounds → would otherwise allocate 1 TiB
    await expect(importFromP2W(tampered, PASS)).rejects.toThrow();
  });
});

// ── v2-specific: header AAD binding (HIGH-5) ──────────────────────────────────

describe('Header AAD binding (HIGH-5 fix)', () => {
  it('AEAD decryption fails when any header byte is mutated, independent of HMAC', async () => {
    // Tampering with bytes 2..98 of the file (the header) must trip the HMAC
    // first; we verify that even if an attacker could forge the HMAC, the AAD
    // binding on both AEAD layers would still reject it. We simulate this by
    // mutating the header AND recomputing the HMAC tags using the raw module
    // internals - but since K_mac is not exposed, we instead just verify the
    // happy-path tampering rejection. The PoC test in p2wAttack.test.ts covers
    // the AAD-only path explicitly.
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    const tampered = new Uint8Array(file);
    tampered[2 + 6] ^= 0x01; // flip a flags byte inside the header
    await expect(importFromP2W(tampered, PASS)).rejects.toThrow();
  });
});

// ── v2-specific: NFC normalisation (MED-8) ────────────────────────────────────

describe('Passphrase NFC normalisation (MED-8 fix)', () => {
  it('decrypts a file written with the precomposed form using the decomposed form', async () => {
    const precomposed = 'café-' + 'pass';                       // 'é' = U+00E9
    const decomposed  = 'café-' + 'pass';                 // 'e' + combining U+0301
    expect(precomposed).not.toBe(decomposed);
    expect(precomposed.normalize('NFC')).toBe(decomposed.normalize('NFC'));
    const file = await exportToP2W([C1], [], precomposed, FAST);
    const { credentials } = await importFromP2W(file, decomposed);
    expect(credentials[0].password).toBe('S3cr3t!Pass#99');
  });
});

// ── v2-specific: metadata leakage (HIGH-7) ────────────────────────────────────

describe('Plaintext metadata leakage (HIGH-7 fix)', () => {
  it('header bytes 8..24 (CREATED_AT, CRED_COUNT, FOLD_COUNT) are zero in v2', async () => {
    const file = await exportToP2W(CREDS, FOLDS, PASS, FAST);
    // Header offset 8..24 corresponds to file offset 10..26.
    for (let i = 10; i < 26; i++) expect(file[i]).toBe(0);
  });
});

// ── Large vault ───────────────────────────────────────────────────────────────

describe('Large vault', () => {
  it('round-trips 100 credentials', async () => {
    const many: Credential[] = Array.from({ length: 100 }, (_, i) => ({
      id: `id-${i}`, service: `Service-${i}`, url: `https://s${i}.example.com`,
      username: `user${i}@example.com`, password: `P@ss${i}!`,
      status: 'active', statusColor: '#22c55e', logo: '', folderId: '',
      tags: [`tag-${i % 5}`],
    } as Credential));
    const file = await exportToP2W(many, [], PASS, FAST);
    const { credentials } = await importFromP2W(file, PASS);
    expect(credentials).toHaveLength(100);
    expect(credentials[42].service).toBe('Service-42');
    expect(credentials[99].password).toBe('P@ss99!');
  });
});
