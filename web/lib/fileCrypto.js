import { readFileSync, writeFileSync, existsSync, renameSync } from 'fs';
import { readFile as readFileAsync, writeFile as writeFileAsync, rename as renameAsync } from 'fs/promises';
import { lock } from 'proper-lockfile';
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  createHmac,
} from 'crypto';
import path from 'path';
import { ctx } from './context.js';

// ── HKDF-derived subkeys ──────────────────────────────────────────────────────
// HKDF-SHA-384 per CNSA 2.0 (NIST SP 800-56C).

export function derivedKey(info, length = 32) {
  const cacheKey = `${info}:${length}`;
  const cached = ctx.derivedKeyCache.get(cacheKey);
  if (cached) return cached;
  const buf = hkdfSync('sha384', ctx.MASTER_KEY, Buffer.alloc(0), Buffer.from(info), length);
  const key = Buffer.from(buf);
  ctx.derivedKeyCache.set(cacheKey, key);
  return key;
}

// ── File-level AES-256-GCM ────────────────────────────────────────────────────

export function encryptBlob(info, plaintext) {
  const key = derivedKey(info);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

export function decryptBlob(info, blob) {
  if (blob.length < 12 + 16) throw new Error('blob too short');
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const key = derivedKey(info);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

export function writeEncryptedFile(filePath, info, jsonValue) {
  const plaintext = Buffer.from(JSON.stringify(jsonValue), 'utf8');
  const blob = encryptBlob(info, plaintext);
  const tmp = filePath + '.tmp';
  writeFileSync(tmp, blob, { mode: 0o600 });
  renameSync(tmp, filePath);
}

export async function writeEncryptedFileAsync(filePath, info, jsonValue) {
  const plaintext = Buffer.from(JSON.stringify(jsonValue), 'utf8');
  const blob = encryptBlob(info, plaintext);
  const tmp = filePath + '.tmp';
  await writeFileAsync(tmp, blob, { mode: 0o600 });
  await renameAsync(tmp, filePath);
}

export function readEncryptedFile(filePath, info, fallback) {
  if (!existsSync(filePath)) return fallback;
  const blob = readFileSync(filePath);
  try {
    const pt = decryptBlob(info, blob);
    return JSON.parse(pt.toString('utf8'));
  } catch {
    return fallback;
  }
}

export async function readEncryptedFileAsync(filePath, info, fallback) {
  if (!existsSync(filePath)) return fallback;
  try {
    const blob = await readFileAsync(filePath);
    const pt = decryptBlob(info, blob);
    return JSON.parse(pt.toString('utf8'));
  } catch {
    return fallback;
  }
}

// Strict reader — returns fallback when absent, throws on AEAD integrity failure.
export function readEncryptedFileStrict(filePath, info, fallback) {
  if (!existsSync(filePath)) return fallback;
  const blob = readFileSync(filePath);
  const pt = decryptBlob(info, blob); // throws on AEAD failure
  return JSON.parse(pt.toString('utf8'));
}

// ── User store ────────────────────────────────────────────────────────────────

export function usersPath()        { return path.join(ctx.DATA_DIR, 'users.enc'); }
export function userVaultDir(uid)  { return path.join(ctx.DATA_DIR, 'vault', uid); }
export function userVaultFile(uid, name) { return path.join(userVaultDir(uid), name + '.enc'); }
export function userInfo(uid, name) { return `vault/${uid}/${name}`; }
export function userSharesDir(uid) { return path.join(ctx.DATA_DIR, 'vault', uid, 'shares'); }

export function loadUsers() {
  // No in-memory cache — every call reads from disk to ensure session revocations
  // are visible immediately across all PM2 workers.
  return readEncryptedFile(usersPath(), 'users/enc', []);
}
export async function loadUsersAsync() {
  return readEncryptedFileAsync(usersPath(), 'users/enc', []);
}
export function saveUsers(users) {
  writeEncryptedFile(usersPath(), 'users/enc', users);
}
export async function saveUsersAsync(users) {
  return writeEncryptedFileAsync(usersPath(), 'users/enc', users);
}

export function hashEmail(email) {
  // HMAC-SHA256 with MASTER_KEY prevents rainbow-table attacks on the users.enc
  // email-hash index — the hash is irreversible without the installation secret.
  return createHmac('sha256', ctx.MASTER_KEY).update(email.trim().toLowerCase(), 'utf8').digest('hex');
}

// ── Locking helpers ───────────────────────────────────────────────────────────

// Pattern A fix: serialise every load → mutate → save sequence on users.enc.
// Contract:
//   await withUsersLock(async (users) => { users[i].field = ...; })
// • The lock is taken on `users.enc` via `proper-lockfile` and held until callback resolves.
// • The callback receives a freshly-read `users` array. Mutate it in place.
// • Return value of the callback is the helper's return value.
// • To opt out of the write (read-only operation), return `false`.
// • Any thrown error releases the lock without writing.
//
// IMPORTANT: avoid putting long-running awaits (Argon2id verify/hash) INSIDE
// the callback — they will serialise all logins.
export async function withUsersLock(fn) {
  const filePath = usersPath();
  if (!existsSync(filePath)) {
    writeEncryptedFile(filePath, 'users/enc', []);
  }
  let release = null;
  try {
    release = await lock(filePath, { retries: { retries: 20, minTimeout: 50, maxTimeout: 500 } });
    const users = readEncryptedFile(filePath, 'users/enc', []);
    const result = await fn(users);
    if (result !== false) {
      saveUsers(users);
    }
    return result;
  } finally {
    if (release) { try { await release(); } catch (_) {} }
  }
}

// Per-user-dir lock — used by recordSession, saveSessions on logout / password
// change / revoke-others. Required to close C-14 and C-15.
export async function withUserDirLock(uid, fn) {
  const { mkdirSync } = await import('fs');
  const dir = userVaultDir(uid);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  let release = null;
  try {
    release = await lock(dir, { retries: { retries: 20, minTimeout: 50, maxTimeout: 500 } });
    return await fn();
  } finally {
    if (release) { try { await release(); } catch (_) {} }
  }
}
