import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, renameSync, rmSync, readdirSync } from 'fs';
import { readFile as readFileAsync, writeFile as writeFileAsync, rename as renameAsync } from 'fs/promises';
import { promisify } from 'util';
import nodemailer from 'nodemailer';
import path from 'path';
import argon2 from 'argon2';
import { lock } from 'proper-lockfile';
import {
  randomBytes,
  randomInt,
  timingSafeEqual,
  scryptSync,
  pbkdf2Sync,
  pbkdf2,
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  createHash,
  createHmac,
} from 'crypto';

// Async PBKDF2 — runs in the libuv thread pool so 1M iterations don't block the event loop.
const pbkdf2Async = promisify(pbkdf2);
// JWE per RFC 7516/7518; alg pinned to "dir" (no algorithm confusion per RFC 8725).
import { EncryptJWT, jwtDecrypt } from 'jose';
import { TOTP } from 'totp-generator';
import { IpIntelligenceService } from './ipIntelligence.js';

// ── Constants ────────────────────────────────────────────────────────────────

const SCRYPT_N = 1 << 17;        // 131072 — legacy verification only
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_LEN = 64;
const SCRYPT_MAXMEM = 256 * 1024 * 1024; // 256 MiB ceiling

// PBKDF2-HMAC-SHA-512, 1,000,000 iterations (CNSA 2.0 requirement).
// Retained for legacy verification only — new hashes use Argon2id.
const PBKDF2_SHA512_ITERS = 1_000_000;
const PBKDF2_SHA512_LEN   = 64; // bytes
const PBKDF2_HASH_PREFIX  = '$pbkdf2sha512$';

// Argon2id parameters per NIST SP 800-63B-4 §5.1.1.2 (AAL3).
// m=128 MiB balances security vs. multi-tenant memory; native argon2 npm uses the
// libuv thread pool so hashing is non-blocking.
const ARGON2_MEMORY_KIB  = 128 * 1024; // 128 MiB
const ARGON2_TIME_COST   = 3;
const ARGON2_PARALLELISM = 1;

// Concurrency gate — at 128 MiB per hash, unconstrained parallelism exhausts RAM.
let   _argon2ActiveCount = 0;
const ARGON2_MAX_CONCURRENT = 3;

const JWE_TTL_SECONDS = 60 * 60 * 24; // 24h absolute
const SESSION_ROLL_SECONDS = 60 * 15; // refresh cookie every 15 min of activity

const COOKIE_SESSION = '_pwd_sess';
const COOKIE_CSRF    = '_pwd_csrf';

// ── Partial MFA tokens ───────────────────────────────────────────────────────
// Pending MFA state is kept in persistent encrypted storage, not in-memory Map,
// so it survives PM2 worker restarts and across cluster workers.
const PARTIAL_MFA_TTL_MS = 5 * 60 * 1000; // 5 minutes

function mfaPendingPath() { return path.join(DATA_DIR, 'mfa_pending.enc'); }
function loadMfaPending() {
  const data = readEncryptedFile(mfaPendingPath(), 'mfa/pending', { tokens: {}, emailOtps: {} });
  // GC expired entries on every load to keep the file bounded.
  const now = Date.now();
  let changed = false;
  for (const [k, v] of Object.entries(data.tokens)) {
    if (now > v.expiresAt) { delete data.tokens[k]; changed = true; }
  }
  for (const [k, v] of Object.entries(data.emailOtps)) {
    if (now > v.expiresAt) { delete data.emailOtps[k]; changed = true; }
  }
  if (changed) saveMfaPending(data);
  return data;
}
function saveMfaPending(data) {
  writeEncryptedFile(mfaPendingPath(), 'mfa/pending', data);
}

// ── Per-IP login rate limiter ─────────────────────────────────────────────────
// Prevents credential-stuffing and Argon2id-DoS. 10 attempts / 5 min per IP.
// In PM2 cluster mode each worker maintains its own counts; a single-worker
// auth process is recommended for accurate enforcement.
const _loginRateLimiter    = new Map(); // ip → { count, resetAt }
const LOGIN_MAX_PER_WINDOW = 10;
const LOGIN_WINDOW_MS      = 5 * 60 * 1000; // 5 min

// Hard-cap Map sizes to prevent OOM under sustained botnet attack.
const MAX_RATE_LIMIT_ENTRIES = 100_000;
function enforceMapCap(map) {
  if (map.size > MAX_RATE_LIMIT_ENTRIES) {
    // Map iterator follows insertion order; evict oldest 1000 entries.
    const it = map.keys();
    for (let i = 0; i < 1000; i++) {
      const { value, done } = it.next();
      if (done) break;
      map.delete(value);
    }
  }
}

function checkLoginRate(ip) {
  const now = Date.now();
  let e = _loginRateLimiter.get(ip);
  if (!e || now > e.resetAt) {
    e = { count: 0, resetAt: now + LOGIN_WINDOW_MS };
    _loginRateLimiter.set(ip, e);
    enforceMapCap(_loginRateLimiter);
  }
  // Immutable update avoids racing mutations between async calls.
  const updated = { ...e, count: e.count + 1 };
  _loginRateLimiter.set(ip, updated);
  return updated.count <= LOGIN_MAX_PER_WINDOW;
}

// Per-account lockout — mirrors daemon's LOCKOUT_SCHEDULE_SECS.
// Blocks distributed attacks (many IPs → one account) regardless of IP diversity.
const _accountLockout = new Map(); // emailHash → { count, lockedUntil }
const ACCOUNT_LOCKOUT_SCHEDULE_MS = [0, 0, 0, 0, 0, 30000, 60000, 120000, 300000, 600000];

function checkAccountRate(emailHash) {
  const now = Date.now();
  const e = _accountLockout.get(emailHash) ?? { count: 0, lockedUntil: 0 };
  if (e.lockedUntil && now < e.lockedUntil) return false; // still locked
  if (e.lockedUntil && now >= e.lockedUntil) {
    e.count = 0; e.lockedUntil = 0; // lockout expired, reset
  }
  return true; // allow — caller increments on failure
}

function recordAccountFailure(emailHash) {
  const e = _accountLockout.get(emailHash) ?? { count: 0, lockedUntil: 0 };
  const count = e.count + 1;
  const lockSecs = ACCOUNT_LOCKOUT_SCHEDULE_MS[Math.min(count, ACCOUNT_LOCKOUT_SCHEDULE_MS.length - 1)];
  const updated = {
    count,
    lockedUntil: lockSecs > 0 ? Date.now() + lockSecs : 0
  };
  _accountLockout.set(emailHash, updated);
  enforceMapCap(_accountLockout);
}

function resetAccountFailures(emailHash) {
  _accountLockout.delete(emailHash);
}

// Per-IP registration rate limiter — prevents mass-registration Argon2id-DoS.
const _registerRateLimiter    = new Map();
const REGISTER_MAX_PER_WINDOW = 5;
const REGISTER_WINDOW_MS      = 60 * 60 * 1000; // 1 hour

function checkRegisterRate(ip) {
  const now = Date.now();
  let e = _registerRateLimiter.get(ip);
  if (!e || now > e.resetAt) {
    e = { count: 0, resetAt: now + REGISTER_WINDOW_MS };
    _registerRateLimiter.set(ip, e);
    enforceMapCap(_registerRateLimiter);
  }
  const updated = { ...e, count: e.count + 1 };
  _registerRateLimiter.set(ip, updated);
  return updated.count <= REGISTER_MAX_PER_WINDOW;
}

// Per-IP emergency-endpoint rate limiter.
const _emergencyRateLimiter    = new Map();
const EMERGENCY_MAX_PER_WINDOW = 5;
const EMERGENCY_WINDOW_MS      = 60 * 1000; // 1 min

function checkEmergencyRate(ip) {
  const now = Date.now();
  let e = _emergencyRateLimiter.get(ip);
  if (!e || now > e.resetAt) {
    e = { count: 0, resetAt: now + EMERGENCY_WINDOW_MS };
    _emergencyRateLimiter.set(ip, e);
    enforceMapCap(_emergencyRateLimiter);
  }
  const updated = { ...e, count: e.count + 1 };
  _emergencyRateLimiter.set(ip, updated);
  return updated.count <= EMERGENCY_MAX_PER_WINDOW;
}

// Periodic cleanup of expired rate-limiter entries.
setInterval(() => {
  const now = Date.now();
  for (const map of [_loginRateLimiter, _registerRateLimiter, _emergencyRateLimiter]) {
    for (const [k, v] of map) { if (now > v.resetAt) map.delete(k); }
  }
}, 5 * 60 * 1000);


// ── #3-FIX: atomic read-modify-write for mfa_pending.enc ─────────────────────
// Every mutation acquires a proper-lockfile lock so PM2 cluster workers cannot
// race and lose tokens or re-consume a consumed OTP (CWE-367).
async function withMfaPendingLock(fn) {
  const filePath = mfaPendingPath();
  // Ensure the file exists; proper-lockfile requires the target to be present.
  if (!existsSync(filePath)) {
    writeEncryptedFile(filePath, 'mfa/pending', { tokens: {}, emailOtps: {} });
  }
  let release = null;
  try {
    release = await lock(filePath, { retries: { retries: 10, minTimeout: 50, maxTimeout: 500 } });
    // GC expired entries under the lock before mutating.
    const data = readEncryptedFile(filePath, 'mfa/pending', { tokens: {}, emailOtps: {} });
    const now = Date.now();
    for (const k of Object.keys(data.tokens)) {
      if (now > data.tokens[k].expiresAt) delete data.tokens[k];
    }
    for (const k of Object.keys(data.emailOtps)) {
      if (now > data.emailOtps[k].expiresAt) delete data.emailOtps[k];
    }
    const result = fn(data);
    saveMfaPending(data);
    return result;
  } finally {
    if (release) { try { await release(); } catch (_) {} }
  }
}

// ── Server-side email OTP store ───────────────────────────────────────────────
// A cryptographically random 6-digit code is generated here, stored keyed by
// sha256(partialToken), and verified with timingSafeEqual in /login/finish.
// Single-use and expires with the parent partialToken (PARTIAL_MFA_TTL_MS).
async function storeEmailOtp(partialToken) {
  const code = randomInt(0, 1_000_000).toString().padStart(6, '0');
  const key  = createHash('sha256').update(partialToken).digest('hex');
  await withMfaPendingLock(data => {
    data.emailOtps[key] = { code, expiresAt: Date.now() + PARTIAL_MFA_TTL_MS };
  });
  return code;
}

async function consumeEmailOtp(partialToken) {
  const key = createHash('sha256').update(partialToken).digest('hex');
  return withMfaPendingLock(data => {
    const entry = data.emailOtps[key];
    if (!entry) return null;
    delete data.emailOtps[key]; // always consume (single-use)
    if (Date.now() > entry.expiresAt) return null;
    return entry.code;
  });
}

// ── MFA brute-force lockout ───────────────────────────────────────────────────
// Without this, an attacker who knows the master password can loop login→finish
// with fresh TOTP guesses indefinitely: /login issues a new partialToken at no
// cost, so there's no penalty per failed /finish call. Per-user failure tracking
// locks the account from MFA for MFA_LOCKOUT_MS after MFA_MAX_ATTEMPTS failures.
const _mfaFailedAttempts = new Map(); // userId → { count, lockedUntil }
const MFA_MAX_ATTEMPTS  = 5;
const MFA_LOCKOUT_MS    = 10 * 60 * 1000; // 10 minutes

function isMfaLocked(userId) {
  const e = _mfaFailedAttempts.get(userId);
  if (!e?.lockedUntil) return false;
  if (Date.now() >= e.lockedUntil) { _mfaFailedAttempts.delete(userId); return false; }
  return true;
}

function recordMfaFailure(userId) {
  const e = _mfaFailedAttempts.get(userId) ?? { count: 0, lockedUntil: 0 };
  e.count++;
  if (e.count >= MFA_MAX_ATTEMPTS) {
    e.lockedUntil = Date.now() + MFA_LOCKOUT_MS;
    e.count = 0;
  }
  _mfaFailedAttempts.set(userId, e);
}

function clearMfaFailure(userId) {
  _mfaFailedAttempts.delete(userId);
}

async function issueMfaToken(userId) {
  const token = randomBytes(32).toString('hex');
  const hash  = createHash('sha256').update(token, 'hex').digest('hex');
  await withMfaPendingLock(data => {
    data.tokens[hash] = { userId, expiresAt: Date.now() + PARTIAL_MFA_TTL_MS };
  });
  return token;
}

async function consumeMfaToken(token) {
  const hash = createHash('sha256').update(token, 'hex').digest('hex');
  return withMfaPendingLock(data => {
    const entry = data.tokens[hash];
    if (!entry) return null;
    delete data.tokens[hash]; // single-use
    if (Date.now() > entry.expiresAt) return null;
    return entry.userId;
  });
}

// ── TOTP verification ─────────────────────────────────────────────────────────
// Per-secret used-period cache prevents replay within the ±1 window.
// Key: sha256(secret) hex; Value: Set of period numbers (floor(ts/30000)).
// Entries older than 2 minutes are pruned to bound memory.
const _usedTotpPeriods = new Map(); // secretHash → Set<period>

setInterval(() => {
  const cutoff = Math.floor(Date.now() / 30000) - 4; // 2 min ago
  for (const [k, periods] of _usedTotpPeriods) {
    for (const p of periods) { if (p < cutoff) periods.delete(p); }
    if (periods.size === 0) _usedTotpPeriods.delete(k);
  }
}, 60_000);

async function verifyTotpCode(secret, code) {
  if (!/^\d{6,8}$/.test(code)) return false;
  const now = Date.now();
  const secretHash = createHash('sha256').update(secret).digest('hex');

  for (const drift of [-30000, 0, 30000]) {
    const ts = now + drift;
    const period = Math.floor(ts / 30000);
    const { otp } = await TOTP.generate(secret, { timestamp: ts });
    if (otp.length === code.length && timingSafeEqual(Buffer.from(otp), Buffer.from(code))) {
      let periods = _usedTotpPeriods.get(secretHash);
      if (!periods) { periods = new Set(); _usedTotpPeriods.set(secretHash, periods); }
      if (periods.has(period)) return false; // replay
      periods.add(period);
      return true;
    }
  }
  return false;
}

// ── Master key ───────────────────────────────────────────────────────────────

let MASTER_KEY = null;
let DATA_DIR = null;
let ipIntel = null;
let ipPolicy = { blockTor: true, blockProxy: true, blockVpn: false, blockAbuser: true };

// Cache HKDF-derived sub-keys — safe because MASTER_KEY is constant after initAuth.
const _derivedKeyCache = new Map();

export function initAuth({ dataDir }) {
  DATA_DIR = dataDir;
  _derivedKeyCache.clear(); // clear on re-init in case MASTER_KEY changes
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  const keyPath = path.join(DATA_DIR, '.master_key');
  if (existsSync(keyPath)) {
    MASTER_KEY = readFileSync(keyPath);
    if (MASTER_KEY.length !== 32) throw new Error('master key file is not 32 bytes');
  } else {
    MASTER_KEY = randomBytes(32);
    writeFileSync(keyPath, MASTER_KEY, { mode: 0o400, flag: 'wx' });
  }
  const usersFile = path.join(DATA_DIR, 'users.enc');
  if (!existsSync(usersFile)) writeEncryptedFile(usersFile, 'users/enc', []);
  const vaultDir = path.join(DATA_DIR, 'vault');
  if (!existsSync(vaultDir)) mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
  ipIntel = new IpIntelligenceService(process.env.IPREGISTRY_API_KEY ?? '', DATA_DIR);
  ipPolicy = loadIpPolicy();
  // Pre-warm to avoid mid-request outbound network calls on the first login.
  getServerPublicIp().catch(() => {});
  // Pre-populate the derived-key cache for the two hottest paths.
  derivedKey('jwe/session', 32);
  derivedKey('users/enc', 32);
}

function derivedKey(info, length = 32) {
  // HKDF-SHA-384 per CNSA 2.0 (NIST SP 800-56C).
  const cacheKey = `${info}:${length}`;
  const cached = _derivedKeyCache.get(cacheKey);
  if (cached) return cached;
  const buf = hkdfSync('sha384', MASTER_KEY, Buffer.alloc(0), Buffer.from(info), length);
  const key = Buffer.from(buf);
  _derivedKeyCache.set(cacheKey, key);
  return key;
}

// ── File-level AES-256-GCM ───────────────────────────────────────────────────

function encryptBlob(info, plaintext) {
  const key = derivedKey(info);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

function decryptBlob(info, blob) {
  if (blob.length < 12 + 16) throw new Error('blob too short');
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const key = derivedKey(info);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

function writeEncryptedFile(filePath, info, jsonValue) {
  const plaintext = Buffer.from(JSON.stringify(jsonValue), 'utf8');
  const blob = encryptBlob(info, plaintext);
  const tmp = filePath + '.tmp';
  writeFileSync(tmp, blob, { mode: 0o600 });
  renameSync(tmp, filePath);
}

async function writeEncryptedFileAsync(filePath, info, jsonValue) {
  const plaintext = Buffer.from(JSON.stringify(jsonValue), 'utf8');
  const blob = encryptBlob(info, plaintext);
  const tmp = filePath + '.tmp';
  await writeFileAsync(tmp, blob, { mode: 0o600 });
  await renameAsync(tmp, filePath);
}

function readEncryptedFile(filePath, info, fallback) {
  if (!existsSync(filePath)) return fallback;
  const blob = readFileSync(filePath);
  try {
    const pt = decryptBlob(info, blob);
    return JSON.parse(pt.toString('utf8'));
  } catch {
    return fallback;
  }
}

async function readEncryptedFileAsync(filePath, info, fallback) {
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
function readEncryptedFileStrict(filePath, info, fallback) {
  if (!existsSync(filePath)) return fallback;
  const blob = readFileSync(filePath);
  const pt = decryptBlob(info, blob); // throws on AEAD failure
  return JSON.parse(pt.toString('utf8'));
}

// ── User store ───────────────────────────────────────────────────────────────

function usersPath()        { return path.join(DATA_DIR, 'users.enc'); }
function userVaultDir(uid)  { return path.join(DATA_DIR, 'vault', uid); }
function userVaultFile(uid, name) { return path.join(userVaultDir(uid), name + '.enc'); }
function userInfo(uid, name) { return `vault/${uid}/${name}`; }
function userSharesDir(uid) { return path.join(DATA_DIR, 'vault', uid, 'shares'); }

function loadUsers() {
  // No in-memory cache — every call reads from disk to ensure session revocations
  // are visible immediately across all PM2 workers.
  return readEncryptedFile(usersPath(), 'users/enc', []);
}
async function loadUsersAsync() {
  return readEncryptedFileAsync(usersPath(), 'users/enc', []);
}
function saveUsers(users) {
  writeEncryptedFile(usersPath(), 'users/enc', users);
}
async function saveUsersAsync(users) {
  return writeEncryptedFileAsync(usersPath(), 'users/enc', users);
}

function hashEmail(email) {
  // HMAC-SHA256 with MASTER_KEY prevents rainbow-table attacks on the users.enc
  // email-hash index — the hash is irreversible without the installation secret.
  return createHmac('sha256', MASTER_KEY).update(email.trim().toLowerCase(), 'utf8').digest('hex');
}

function scryptHash(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const pwdBuf = Buffer.from(password, 'utf8');
  const out = scryptSync(pwdBuf, salt, SCRYPT_LEN, {
    N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: SCRYPT_MAXMEM,
  });
  pwdBuf.fill(0);
  return out.toString('hex');
}

// PBKDF2-SHA-512, 1M iterations (CNSA 2.0). Format: `$pbkdf2sha512$<saltHex>$<hashHex>`.
// Async so the computation runs in the libuv thread pool.
async function pbkdf2Sha512Hash(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const hash = await pbkdf2Async(Buffer.from(password, 'utf8'), salt, PBKDF2_SHA512_ITERS, PBKDF2_SHA512_LEN, 'sha512');
  return `${PBKDF2_HASH_PREFIX}${saltHex}$${hash.toString('hex')}`;
}

async function pbkdf2Sha512Verify(stored, password) {
  if (!stored.startsWith(PBKDF2_HASH_PREFIX)) return false;
  const parts = stored.slice(PBKDF2_HASH_PREFIX.length).split('$');
  if (parts.length !== 2) return false;
  const [saltHex, expectedHex] = parts;
  const salt = Buffer.from(saltHex, 'hex');
  const actual = await pbkdf2Async(Buffer.from(password, 'utf8'), salt, PBKDF2_SHA512_ITERS, PBKDF2_SHA512_LEN, 'sha512');
  const expected = Buffer.from(expectedHex, 'hex');
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}

async function hashPassword(password) {
  if (_argon2ActiveCount >= ARGON2_MAX_CONCURRENT) {
    const err = new Error('too_many_requests');
    err.status = 429;
    throw err;
  }
  _argon2ActiveCount++;
  try {
    return await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: ARGON2_MEMORY_KIB,
      timeCost: ARGON2_TIME_COST,
      parallelism: ARGON2_PARALLELISM,
    });
  } finally {
    _argon2ActiveCount--;
  }
}

async function verifyPassword(hashOrLegacy, password, legacySaltHex) {
  if (_argon2ActiveCount >= ARGON2_MAX_CONCURRENT) {
    const err = new Error('too_many_requests');
    err.status = 429;
    throw err;
  }
  _argon2ActiveCount++;
  try {
    // Primary path
    if (hashOrLegacy && hashOrLegacy.startsWith('$argon2id$')) {
      return await argon2.verify(hashOrLegacy, password);
    }
    // Legacy: PBKDF2-SHA-512
    if (hashOrLegacy && hashOrLegacy.startsWith(PBKDF2_HASH_PREFIX)) {
      return await pbkdf2Sha512Verify(hashOrLegacy, password);
    }
    // Legacy: argon2i/argon2d variants
    if (hashOrLegacy && hashOrLegacy.startsWith('$argon2')) {
      return await argon2.verify(hashOrLegacy, password);
    }
    if (!hashOrLegacy || !legacySaltHex) {
      // Dummy stretch to prevent user-enumeration timing oracle.
      // Must use the same algorithm and parameters as the primary path.
      const DUMMY_HASH = '$argon2id$v=19$m=131072,t=3,p=1$c29tZXNhbHQ$c29tZWhhc2hvdXRwdXQ';
      await argon2.verify(DUMMY_HASH, password).catch(() => {});
      return false;
    }
    // Oldest legacy: scrypt
    const hash = scryptHash(password, legacySaltHex);
    return constEq(hash, hashOrLegacy);
  } finally {
    _argon2ActiveCount--;
  }
}

function constEq(a, b) {
  const ab = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function generateUUID() {
  return randomBytes(16).toString('hex');
}

// ── JWT / Session ────────────────────────────────────────────────────────────

async function issueJwt(userId) {
  const jti = randomBytes(16).toString('hex');
  const secret = derivedKey('jwe/session');
  const token = await new EncryptJWT({})
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .setSubject(userId)
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime(`${JWE_TTL_SECONDS}s`)
    .encrypt(secret);
  return { token, jti };
}

async function verifyJwt(token) {
  try {
    const secret = derivedKey('jwe/session');
    const { payload } = await jwtDecrypt(token, secret);
    return payload;
  } catch {
    return null;
  }
}

function setSessionCookies(req, res, token, csrf) {
  // req.secure is correctly set by Express when trust proxy = loopback.
  // Without trust proxy, it would always be false behind Nginx → Secure flag missing.
  const isSecure = req.secure;
  const common = { httpOnly: true, secure: isSecure, sameSite: 'Strict', path: '/' };
  res.cookie(COOKIE_SESSION, token, common);
  res.cookie(COOKIE_CSRF, csrf, { ...common, httpOnly: false });
}

function clearSessionCookies(req, res) {
  const isSecure = req.secure;
  const common = { httpOnly: true, secure: isSecure, sameSite: 'Strict', path: '/' };
  res.clearCookie(COOKIE_SESSION, common);
  res.clearCookie(COOKIE_CSRF, { ...common, httpOnly: false });
}

async function authMiddleware(req, _res, next) {
  const token = req.cookies?.[COOKIE_SESSION];
  if (!token) { req.user = null; return next(); }
  const payload = await verifyJwt(token);
  if (!payload) { req.user = null; return next(); }
  const users = loadUsers();
  const u = users.find(x => x.id === payload.sub);
  if (!u) { req.user = null; return next(); }

  // Ensure jti is still active (not revoked by logout or password change).
  // The active JTI list must never appear in production logs (leaks session data).
  const activeSessions = loadSessions(u.id);
  const isActive = activeSessions.some(s => s.jti === payload.jti);
  if (!isActive) {
    req.user = null;
    return next();
  }

  req.user = { id: u.id, emailHash: u.emailHash, jti: payload.jti, exp: payload.exp };
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'unauthenticated' });
  next();
}

function requireCsrf(req, res, next) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  const header = req.headers['x-csrf-token'];
  const cookie = req.cookies?.[COOKIE_CSRF];
  if (!header || !cookie || typeof header !== 'string' || header !== cookie) {
    return res.status(403).json({ error: 'csrf' });
  }
  next();
}

// ── Session Audit Log ────────────────────────────────────────────────────────

function sessionsPath(uid) { return path.join(userVaultDir(uid), 'sessions.enc'); }

// Sessions cache is intentionally disabled (TTL = 0). In PM2 cluster mode,
// a non-zero TTL would mean password-change / logout revocations only take
// effect on the worker that handled the request — other workers would keep
// serving the old session for up to TTL ms. The cost is one AES-GCM decrypt
// per authenticated request, acceptable for a self-hosted deployment.
const _sessionsCache = new Map(); // uid → { data: Array, ts: number }
const SESSIONS_CACHE_TTL_MS = 0;

function loadSessions(uid) {
  const entry = _sessionsCache.get(uid);
  if (entry && Date.now() - entry.ts < SESSIONS_CACHE_TTL_MS) return entry.data;
  const data = readEncryptedFile(sessionsPath(uid), userInfo(uid, 'sessions'), []);
  _sessionsCache.set(uid, { data, ts: Date.now() });
  return data;
}
function saveSessions(uid, list) {
  writeEncryptedFile(sessionsPath(uid), userInfo(uid, 'sessions'), list);
  _sessionsCache.set(uid, { data: list, ts: Date.now() });
}

function parseUA(ua) {
  const os =
    /Macintosh|Mac OS X/i.test(ua) ? 'macOS' :
    /Windows NT 10/i.test(ua)      ? 'Windows 10/11' :
    /Windows/i.test(ua)            ? 'Windows' :
    /iPhone|iPad/i.test(ua)        ? 'iOS' :
    /Android/i.test(ua)            ? 'Android' :
    /Linux/i.test(ua)              ? 'Linux' : 'Unknown OS';
  
  // Brave UA is identical to Chrome; sessionTracker.ts passes the real name when available.
  const br =
    /Vivaldi/i.test(ua)                            ? 'Vivaldi' :
    /Edg\//i.test(ua)                              ? 'Edge' :
    /OPR\//i.test(ua) || /Opera/i.test(ua)         ? 'Opera' :
    /Chrome\/\d/i.test(ua) && !/Chromium/i.test(ua) ? 'Chrome' :
    /Firefox\/\d/i.test(ua)                        ? 'Firefox' :
    /Safari\/\d/i.test(ua)                         ? 'Safari' : 'Unknown Browser';
  return `${os} - ${br}`;
}

function getClientIp(req) {
  // req.ip honours app.set('trust proxy','loopback') — returns X-Real-IP behind
  // Nginx, or the raw socket address for direct connections.
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

// ── IP Policy ─────────────────────────────────────────────────────────────────
function parseBoolEnv(key, defaultVal) {
  const v = process.env[key];
  if (v === undefined || v === '') return defaultVal;
  return v === 'true' || v === '1';
}
function loadIpPolicy() {
  return {
    blockTor:    parseBoolEnv('IP_BLOCK_TOR',    true),
    blockProxy:  parseBoolEnv('IP_BLOCK_PROXY',  true),
    blockVpn:    parseBoolEnv('IP_BLOCK_VPN',    false),
    blockAbuser: parseBoolEnv('IP_BLOCK_ABUSER', true),
  };
}

// ── Audit Log ─────────────────────────────────────────────────────────────────
function auditLogPath(uid) { return path.join(userVaultDir(uid), 'audit_log.enc'); }
function loadAuditLog(uid) {
  const events = readEncryptedFile(auditLogPath(uid), userInfo(uid, 'audit_log'), []);
  // Verify HMAC integrity chain to detect log excision or tampering.
  if (events.length > 0) {
    const key = derivedKey('audit/chain');
    let prevHash = '0'.repeat(64);
    for (const e of events) {
      const { hash, integrity_failure: _ignored, ...data } = e;
      if (!hash) {
        e.integrity_failure = true;
        continue;
      }
      const expected = createHmac('sha256', key).update(JSON.stringify(data) + prevHash).digest('hex');
      if (hash !== expected) {
        console.error(`[audit] Integrity chain broken at event ${e.id} for user ${uid}`);
        e.integrity_failure = true;
      }
      prevHash = hash;
    }
  }
  return events;
}
function saveAuditLog(uid, events) {
  writeEncryptedFile(auditLogPath(uid), userInfo(uid, 'audit_log'), events);
}
function compactIpInfo(record) {
  if (!record) return null;
  return {
    country: record.country, countryCode: record.countryCode,
    countryFlag: record.countryFlag, city: record.city,
    region: record.region, org: record.org,
    connectionType: record.connectionType, riskFlags: record.riskFlags,
  };
}

// Cache the server's outbound public IP (used when client IP is loopback).
// 24-hour persistent cache avoids beaconing on every restart.
let _serverPublicIp = null;
let _serverPublicIpLastFetch = 0;
const PUBLIC_IP_CACHE_MS = 24 * 60 * 60 * 1000;

export async function getServerPublicIp() {
  const cachePath = path.join(DATA_DIR, 'public_ip_cache.json');
  const now = Date.now();

  if (!_serverPublicIp && existsSync(cachePath)) {
    try {
      const data = JSON.parse(readFileSync(cachePath, 'utf8'));
      _serverPublicIp = data.ip;
      _serverPublicIpLastFetch = data.timestamp;
    } catch { /* ignore corrupt cache */ }
  }

  if (_serverPublicIp && (now - _serverPublicIpLastFetch < PUBLIC_IP_CACHE_MS)) {
    return _serverPublicIp;
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const r = await fetch('https://api64.ipify.org?format=json', { signal: controller.signal });
    clearTimeout(timer);
    const data = await r.json();
    _serverPublicIp = data.ip || null;
    _serverPublicIpLastFetch = now;
    // Persist to disk
    try {
      writeFileSync(cachePath, JSON.stringify({ ip: _serverPublicIp, timestamp: now }), { mode: 0o600 });
    } catch { /* ignore write failure */ }
  } catch {
    // Keep stale IP if fetch fails
  }
  return _serverPublicIp;
}

const LOOPBACK_RE = /^(127\.|::1$|::ffff:127\.)/;
const _auditQueue = [];
let _isFlushingAudits = false;

// Audit events are written via an in-memory queue and async flush to prevent the
// per-user-dir lock from serializing requests on every authenticated call.
async function flushAuditQueue() {
  if (_isFlushingAudits || _auditQueue.length === 0) return;
  _isFlushingAudits = true;
  try {
    while (_auditQueue.length > 0) {
      const { uid, event } = _auditQueue.shift();
      await processAuditEvent(uid, event).catch(e => {
        console.error(`[auth] Failed to process audit event for ${uid}:`, e.message);
      });
    }
  } finally {
    _isFlushingAudits = false;
    if (_auditQueue.length > 0) setTimeout(flushAuditQueue, 100);
  }
}

async function processAuditEvent(uid, event) {
  const dir = userVaultDir(uid);
  if (!existsSync(dir)) return;

  let release = null;
  try {
    release = await lock(dir, { retries: { retries: 20, minTimeout: 100, maxTimeout: 1000 } });
    
    let enriched = { ...event };
    // Enrich loopback IPs with the server's real outbound public IP.
    if (LOOPBACK_RE.test(enriched.ip || '')) {
      const publicIp = await getServerPublicIp();
      if (publicIp) {
        enriched.publicIp = publicIp;
        if (ipIntel?.isEnabled() && !enriched.ipInfo) {
          const record = await ipIntel.lookup(publicIp);
          if (record) enriched.ipInfo = compactIpInfo(record);
        }
      }
    }

    const events = loadAuditLog(uid);
    const lastEvent = events[events.length - 1];
    const prevHash = lastEvent?.hash || '0'.repeat(64);

    const newEvent = { id: generateUUID(), ts: Date.now(), ...enriched };
    
    const key = derivedKey('audit/chain');
    newEvent.hash = createHmac('sha256', key).update(JSON.stringify(newEvent) + prevHash).digest('hex');

    events.push(newEvent);
    
    // Ring-buffer cap: 2000 events max to avoid excessive I/O overhead on every append.
    const trimmed = events.length > 2000 ? events.slice(events.length - 2000) : events;
    saveAuditLog(uid, trimmed);
  } finally {
    if (release) await release().catch(() => {});
  }
}

function appendAuditEvent(uid, event) {
  // Cap queue size to prevent memory exhaustion if the flush stalls.
  if (_auditQueue.length < 5000) {
    _auditQueue.push({ uid, event });
    flushAuditQueue().catch(() => {});
  } else {
    console.warn('[auth] Audit queue full - dropping event');
  }
}

// ── IP Blocking Middleware ─────────────────────────────────────────────────────
async function ipBlockingMiddleware(req, res, next) {
  if (!ipIntel || !ipIntel.isEnabled()) return next();
  const ip = getClientIp(req);
  try {
    const record = await ipIntel.lookup(ip);
    req.ipRecord = record || null;
    if (record && ipIntel.isThreat(record, ipPolicy)) {
      console.warn('[ipBlock] Blocked', ip, 'flags:', record.riskFlags.join(','));
      return res.status(403).json({ error: 'access_denied' });
    }
  } catch (err) {
    console.warn('[ipBlock] middleware error:', err.message);
  }
  next();
}

async function recordSession(uid, jti, req) {
  let release = null;
  try {
    const dir = userVaultDir(uid);
    if (existsSync(dir)) {
      release = await lock(dir, { retries: { retries: 10, minTimeout: 100 } });
    }
    const { browser: browserHint } = req.body || {};
    const ua = req.headers['user-agent'] || '';
    const ip = getClientIp(req);
    const all = loadSessions(uid).filter(s => s.jti !== jti);
    const updated = all.map(s => ({ ...s, isCurrent: false }));

    let deviceName = parseUA(ua);
    const safeBrowserHint = typeof browserHint === 'string'
      ? browserHint.slice(0, 50).replace(/[^\w\s\-.]+/g, '')
      : null;
    if (safeBrowserHint && safeBrowserHint !== 'Unknown' && deviceName.includes('Chrome')) {
      deviceName = deviceName.replace('Chrome', safeBrowserHint);
    }

    const isLoopback = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
    let displayIp;
    if (isLoopback) {
      // Use the server's real outbound public IP so the UI shows something meaningful
      displayIp = (await getServerPublicIp()) || 'Local';
    } else {
      const dailySalt = new Date().toISOString().slice(0, 10);
      displayIp = createHash('sha256').update(ip + dailySalt).digest('hex').substring(0, 8);
    }

    updated.push({
      jti,
      id: jti, // use jti as unique id
      timestamp: Date.now(),
      deviceName,
      ip:         displayIp,
      isCurrent:  true,
    });
    const trimmed = updated.length > 20 ? updated.slice(updated.length - 20) : updated;
    saveSessions(uid, trimmed);
  } finally {
    if (release) await release().catch(() => {});
  }
}

// ── Public route mounter ─────────────────────────────────────────────────────

export function mountAuthAndVault(app) {
  app.use(ipBlockingMiddleware);

  // ── Auth ───────────────────────────────────────────────────────────────────

  app.get('/api/auth/me', authMiddleware, (req, res) => {
    if (!req.user) return res.json({ authenticated: false });
    const users = loadUsers();
    const u = users.find(x => x.id === req.user.id);
    if (!u) return res.json({ authenticated: false });
    const profile = readEncryptedFile(userVaultFile(u.id, 'profile'), userInfo(u.id, 'profile'),
      { firstName: '', lastName: '', email: '' });
    res.json({
      authenticated: true,
      user: { 
        firstName: profile.firstName, 
        lastName: profile.lastName, 
        email: profile.email, 
        passwordChangedAt: u.passwordChangedAt,
        recoveryKeyGeneratedAt: u.recoveryKeyGeneratedAt
      },
    });
  });

  app.post('/api/auth/register', authMiddleware, async (req, res) => {
    if (!checkRegisterRate(getClientIp(req))) {
      return res.status(429).json({ error: 'too_many_requests' });
    }
    const { email, password, firstName, lastName, cryptoSalt } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string' ||
        typeof firstName !== 'string' || typeof lastName !== 'string') {
      return res.status(400).json({ error: 'invalid_input' });
    }
    if (password.length < 12) return res.status(400).json({ error: 'weak_password' });

    const emailHash = hashEmail(email);
    const users = loadUsers();
    if (users.some(x => x.emailHash === emailHash)) {
      return res.status(409).json({ error: 'email_taken' });
    }

    let hash;
    try { hash = await hashPassword(password); }
    catch (e) { return res.status(e.status || 500).json({ error: e.message }); }
    const id = randomBytes(16).toString('hex');
    // cryptoSalt is for frontend PBKDF2 key derivation; 'salt' is for server-side hashing.
    users.push({ id, emailHash, passwordHash: hash, salt: null, cryptoSalt: cryptoSalt || null, createdAt: Date.now() });
    saveUsers(users);
    mkdirSync(userVaultDir(id), { recursive: true, mode: 0o700 });
    writeEncryptedFile(userVaultFile(id, 'profile'), userInfo(id, 'profile'),
      { firstName, lastName, email: email.trim() });
    writeEncryptedFile(userVaultFile(id, 'credentials'), userInfo(id, 'credentials'), []);
    writeEncryptedFile(userVaultFile(id, 'folders'),     userInfo(id, 'folders'), []);
    writeEncryptedFile(userVaultFile(id, 'asset_holder'), userInfo(id, 'asset_holder'),
      { emails: [], phoneNumbers: [], u2fKeys: [] });

    const { token, jti } = await issueJwt(id);
    const csrf = randomBytes(24).toString('hex');
    setSessionCookies(req, res, token, csrf);
    await recordSession(id, jti, req);
    res.json({ ok: true });
  });

  // POST body (not query param) for email avoids leaking it in server access logs.
  app.post('/api/auth/login-hints', async (req, res) => {
    const { email, hints } = req.body || {};

    if (hints) { // Sync hints (authenticated write)
      return authMiddleware(req, res, () => {
        return requireAuth(req, res, () => {
          return requireCsrf(req, res, () => {
            const users = loadUsers();
            const userIndex = users.findIndex(x => x.id === req.user.id);
            if (userIndex === -1) return res.status(401).json({ error: 'user_not_found' });
            // #7-FIX: validate and allow-list loginHints keys/values (CWE-915).
            const SAFE_KEYS = new Set(['totp','emailOtp','webauthn','passkey','platform','passwordEnabled','passwordlessEnabled']);
            if (!hints || typeof hints !== 'object' || Array.isArray(hints)) {
              return res.status(400).json({ error: 'invalid_hints' });
            }
            const sanitized = {};
            for (const k of Object.keys(hints)) {
              if (!SAFE_KEYS.has(k)) continue;
              if (typeof hints[k] !== 'boolean') continue;
              sanitized[k] = hints[k];
            }
            users[userIndex].loginHints = sanitized;
            saveUsers(users);
            return res.json({ ok: true });
          });
        });
      });
    }

    // #4-FIX: rate-limit the unauthenticated lookup path (CWE-307).
    if (!checkLoginRate(getClientIp(req))) {
      return res.status(429).json({ error: 'too_many_requests' });
    }

    if (typeof email !== 'string') return res.status(400).json({ error: 'invalid_input' });
    const emailHash = hashEmail(email); // always run to equalise timing
    const users = loadUsers();
    const u = users.find(x => x.emailHash === emailHash);
    // #4-FIX: always return the exact same shape so email existence is not detectable.
    const defaults = { totp: false, emailOtp: false, passwordEnabled: true, webauthn: false, passwordlessEnabled: false };
    if (!u || !u.loginHints) {
      return res.json({ hints: defaults });
    }
    // Strip cryptoSalt that older code may have accidentally persisted in loginHints.
    const { cryptoSalt: _removed, ...rawHints } = u.loginHints;
    // Only return the known safe boolean fields to avoid leaking unexpected properties.
    const safeHints = {};
    for (const k of Object.keys(defaults)) {
      if (typeof rawHints[k] === 'boolean') safeHints[k] = rawHints[k];
    }
    return res.json({ hints: { ...defaults, ...safeHints } });
  });

  // Store the browser-side PBKDF2 salt server-side so it survives browser cache
  // clears. Without server persistence, a new random salt is generated on each
  // login, producing a different AES-GCM key that cannot decrypt existing vault data.
  app.post('/api/auth/crypto-salt', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { cryptoSalt } = req.body || {};
    if (typeof cryptoSalt !== 'string' || !/^[0-9a-f]{32}$/i.test(cryptoSalt)) {
      return res.status(400).json({ error: 'invalid_salt' });
    }
    const users = loadUsers();
    const userIndex = users.findIndex(x => x.id === req.user.id);
    if (userIndex === -1) return res.status(401).json({ error: 'user_not_found' });
    // Never overwrite an existing cryptoSalt — that would make previously encrypted data unreadable.
    if (!users[userIndex].cryptoSalt) {
      users[userIndex].cryptoSalt = cryptoSalt;
      saveUsers(users);
    if (process.env.NODE_ENV !== 'production') {
      console.log(`[auth] Stored cryptoSalt for user ${req.user.id}`);
    }
    }
    // Return cryptoSalt via header — not response body — to avoid capture by body-loggers.
    if (users[userIndex].cryptoSalt) res.setHeader('X-Vault-Salt', users[userIndex].cryptoSalt);
    res.json({ ok: true });
  });

  app.post('/api/auth/login', authMiddleware, async (req, res) => {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'invalid_input' });
    }
    const emailHash = hashEmail(email);

    // Per-account lockout checked before IP rate limit to preserve consistent timing.
    if (!checkAccountRate(emailHash)) {
      return res.status(429).json({ ok: false, error: 'account_locked' });
    }

    if (!checkLoginRate(getClientIp(req))) {
      return res.status(429).json({ ok: false, error: 'too_many_requests' });
    }

    const users = loadUsers();
    const u = users.find(x => x.emailHash === emailHash);

    // Always run verifyPassword even when user is not found — prevents timing-based user enumeration.
    let authenticated = await verifyPassword(u?.passwordHash, password, u?.salt);
    let authMethod = 'password';

    // Recovery key fallback — revoke on first successful use (single-use semantic)
    // and reject if expired (90-day TTL).
    if (u && !authenticated && u.recoveryKeyHash) {
      const expired = u.recoveryKeyExpiresAt && Date.now() > u.recoveryKeyExpiresAt;
      if (!expired && await verifyPassword(u.recoveryKeyHash, password, u.recoveryKeySalt)) {
        authenticated = true;
        authMethod = 'recovery_key';
        u.recoveryKeyHash = null;
        u.recoveryKeySalt = null;
        u.recoveryKeyExpiresAt = null;
        // saveUsers is called below if rehash is triggered; ensure it happens here too.
        const uIdx = users.findIndex(x => x.id === u.id);
        if (uIdx !== -1) {
          users[uIdx].recoveryKeyHash = null;
          users[uIdx].recoveryKeySalt = null;
          users[uIdx].recoveryKeyExpiresAt = null;
        }
        saveUsers(users);
      }
    }

    if (authenticated && u && u.passwordHash && !u.passwordHash.startsWith('$argon2id$')) {
      // Opportunistic rehash: upgrade PBKDF2 / scrypt / argon2i / argon2d → argon2id on login.
      u.passwordHash = await hashPassword(password);
      u.salt = null;
      saveUsers(users);
    }
    if (!authenticated) {
      recordAccountFailure(emailHash);
      if (u) appendAuditEvent(u.id, { action: 'login_failed', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: false, riskFlags: req.ipRecord?.riskFlags ?? [] });
      return res.status(200).json({ ok: false, error: 'invalid_credentials' });
    }
    resetAccountFailures(emailHash);

    // Enforce MFA using server-authoritative plaintext flags written by PUT /api/vault/mfa.
    // The encrypted mfa_config blob is intentionally unreadable by the server (client-side key);
    // `mfaEnforce` is a separate plaintext record written at MFA config time.
    const mfaEnforce = u.mfaEnforce || {};
    const mfaMethods = [];
    if (mfaEnforce.totp  === true) mfaMethods.push('totp');
    if (mfaEnforce.email === true) mfaMethods.push('email');

    // Server-mode cannot verify WebAuthn assertions (no stored COSE public keys).
    // If the user enrolled ONLY hardware MFA (passkey / platform / security-key) without
    // a server-verifiable method (TOTP / email), a password-only login would silently
    // bypass MFA. Block and require daemon-mode login instead.
    const mfaCfg = readUserBlob(u.id, 'mfa_config', {});
    const hasHardwareMfa = (
      (mfaCfg.webauthn?.enabled && (mfaCfg.webauthn?.credentials?.length ?? 0) > 0) ||
      (mfaCfg.passkey?.enabled  && (mfaCfg.passkey?.credentials?.length  ?? 0) > 0) ||
      (mfaCfg.platform?.enabled && (mfaCfg.platform?.credentials?.length ?? 0) > 0)
    );
    if (hasHardwareMfa && mfaMethods.length === 0) {
      appendAuditEvent(u.id, { action: 'login_blocked_hardware_mfa', ip: getClientIp(req), success: false });
      return res.status(403).json({ ok: false, error: 'hardware_mfa_requires_daemon' });
    }

    if (mfaMethods.length > 0) {
      if (isMfaLocked(u.id)) {
        return res.status(429).json({ ok: false, error: 'mfa_locked' });
      }
      const partialToken = await issueMfaToken(u.id);
      if (mfaMethods.includes('email')) {
        const otp = await storeEmailOtp(partialToken);
        // #8-FIX: OTPs must never be logged regardless of NODE_ENV (CWE-532).
        // Send via SMTP when configured. For dev, pipe to a local SMTP stub instead.
        void otp; // suppress unused-var lint; remove when SMTP is wired up
      }
      return res.json({ ok: true, partialToken, methods: mfaMethods });
    }

    const { token, jti } = await issueJwt(u.id);
    const csrf = randomBytes(24).toString('hex');
    setSessionCookies(req, res, token, csrf);
    await recordSession(u.id, jti, req);
    appendAuditEvent(u.id, { action: 'login', auth_method: authMethod, ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    // Return cryptoSalt via header — not response body — to avoid capture by body-loggers.
    if (u.cryptoSalt) res.setHeader('X-Vault-Salt', u.cryptoSalt);
    res.json({ ok: true });
  });

  // Complete the MFA challenge and issue a full session.
  app.post('/api/auth/login/finish', authMiddleware, async (req, res) => {
    const { partialToken, totpCode, emailCode } = req.body || {};
    if (typeof partialToken !== 'string') return res.status(400).json({ error: 'invalid_input' });

    const userId = await consumeMfaToken(partialToken);
    if (!userId) return res.status(401).json({ ok: false, error: 'invalid_or_expired_mfa_token' });

    const users = loadUsers();
    const u = users.find(x => x.id === userId);
    if (!u) return res.status(401).json({ ok: false, error: 'user_not_found' });

    const mfaEnforce = u.mfaEnforce || {};

    if (isMfaLocked(u.id)) {
      return res.status(429).json({ ok: false, error: 'mfa_locked' });
    }

    if (mfaEnforce.totp && u.mfaTotpSecret) {
      const code = totpCode ?? emailCode;
      if (typeof code !== 'string') return res.status(401).json({ ok: false, error: 'mfa_required' });
      if (!await verifyTotpCode(u.mfaTotpSecret, code)) {
        recordMfaFailure(u.id);
        appendAuditEvent(u.id, { action: 'mfa_failed', ip: getClientIp(req), success: false });
        return res.status(401).json({ ok: false, error: 'invalid_mfa_code' });
      }
    } else if (mfaEnforce.email) {
      // consumeEmailOtp looks up the code generated in /login keyed by partialToken
      // (still in scope); single-use, verified with timingSafeEqual.
      if (typeof emailCode !== 'string') {
        return res.status(401).json({ ok: false, error: 'mfa_required' });
      }
      const stored = await consumeEmailOtp(partialToken);
      if (!stored) {
        recordMfaFailure(u.id);
        appendAuditEvent(u.id, { action: 'mfa_failed', ip: getClientIp(req), success: false });
        return res.status(401).json({ ok: false, error: 'invalid_mfa_code' });
      }
      const supplied = emailCode.trim().slice(0, 8); // normalise, cap length
      const match = supplied.length === stored.length &&
        timingSafeEqual(Buffer.from(supplied), Buffer.from(stored));
      if (!match) {
        recordMfaFailure(u.id);
        appendAuditEvent(u.id, { action: 'mfa_failed', ip: getClientIp(req), success: false });
        return res.status(401).json({ ok: false, error: 'invalid_mfa_code' });
      }
    }

    clearMfaFailure(u.id);
    const { token, jti } = await issueJwt(userId);
    const csrf = randomBytes(24).toString('hex');
    setSessionCookies(req, res, token, csrf);
    await recordSession(userId, jti, req);
    appendAuditEvent(userId, { action: 'login', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    if (u.cryptoSalt) res.setHeader('X-Vault-Salt', u.cryptoSalt);
    res.json({ ok: true });
  });

  app.post('/api/auth/recovery-key', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { recoveryKey, password } = req.body || {};
    if (typeof recoveryKey !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'invalid_input' });
    }

    // Crockford-Base32 excludes I, L, O (visual confusion) and U ("accidental profanity").
    if (recoveryKey.length < 26) {
      return res.status(400).json({ error: 'weak_recovery_key' });
    }
    const cleanKey = recoveryKey.replace(/[-\s]/g, '');
    const crockfordRegex = /^[0-9A-HJKMNP-TV-Z]+$/i; // Crockford-Base32 strict
    if (!crockfordRegex.test(cleanKey)) {
      return res.status(400).json({ error: 'invalid_charset' });
    }

    const users = loadUsers();
    const uIndex = users.findIndex(x => x.id === req.user.id);
    if (uIndex === -1) return res.status(401).json({ error: 'user_not_found' });
    const u = users[uIndex];

    // Require password re-verification before allowing recovery-key rotation.
    const verified = await verifyPassword(u.passwordHash, password, u.salt);
    if (!verified) {
      return res.status(401).json({ error: 'invalid_password' });
    }

    const hash = await hashPassword(recoveryKey);

    users[uIndex].recoveryKeyHash = hash;
    users[uIndex].recoveryKeySalt = null; // Argon2id embeds salt in the hash string
    users[uIndex].recoveryKeyGeneratedAt = Date.now();
    // Recovery key expires after 90 days to force periodic re-issue.
    users[uIndex].recoveryKeyExpiresAt = Date.now() + 90 * 24 * 60 * 60 * 1000;
    saveUsers(users);

    res.json({ ok: true });
  });

  // Rate limited to prevent authenticated brute-force of the master password.
  app.post('/api/auth/verify-password', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!checkLoginRate(getClientIp(req))) {
      return res.status(429).json({ error: 'too_many_requests' });
    }
    try {
      const { password } = req.body || {};
      if (typeof password !== 'string') return res.status(400).json({ error: 'invalid_input' });
      const users = loadUsers();
      const u = users.find(x => x.id === req.user.id);
      if (!u) return res.status(401).json({ error: 'user_not_found' });

      // Per-account lockout applies even for non-destructive re-verify (prevents brute-force).
      if (isMfaLocked(u.id)) {
        return res.status(429).json({ ok: false, error: 'too_many_attempts' });
      }

      const authenticated = await verifyPassword(u.passwordHash, password, u.salt);
      if (!authenticated) {
        recordMfaFailure(u.id);
        return res.json({ ok: false });
      }
      clearMfaFailure(u.id);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'server_error' });
    }
  });

  app.post('/api/auth/password', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { oldPassword, newPassword } = req.body || {};
    if (typeof oldPassword !== 'string' || typeof newPassword !== 'string') {
      return res.status(400).json({ error: 'invalid_input' });
    }
    if (newPassword.length < 12) return res.status(400).json({ error: 'weak_password' });

    const users = loadUsers();
    const uIndex = users.findIndex(x => x.id === req.user.id);
    if (uIndex === -1) return res.status(401).json({ error: 'user_not_found' });
    
    const u = users[uIndex];
    const authenticated = await verifyPassword(u.passwordHash, oldPassword, u.salt);
    if (!authenticated) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    const newHash = await hashPassword(newPassword);
    users[uIndex].salt = null;
    users[uIndex].passwordHash = newHash;
    users[uIndex].passwordChangedAt = Date.now();
    saveUsers(users);
    // Invalidate all sessions on password change — the current session is re-issued
    // on next login; the old JTIs are cleared here.
    saveSessions(req.user.id, []);
    appendAuditEvent(req.user.id, { action: 'password_changed', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true });
  });

  app.get('/api/auth/sessions', authMiddleware, requireAuth, (req, res) => {
    // Strip jti from the response — it is an internal detail. The public `id` field
    // (equal to jti) is used for revocation.
    const list = loadSessions(req.user.id)
      .slice()
      .sort((a, b) => b.timestamp - a.timestamp)
      .map(({ jti: _jti, ...rest }) => rest);
    res.json(list);
  });

  app.post('/api/auth/sessions/revoke-others', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const list = loadSessions(req.user.id).filter(s => s.jti === req.user.jti);
    saveSessions(req.user.id, list);
    res.json({ ok: true });
  });

  app.post('/api/auth/logout', authMiddleware, requireCsrf, (req, res) => {
    if (req.user) {
      const list = loadSessions(req.user.id).filter(s => s.jti !== req.user.jti);
      saveSessions(req.user.id, list);
      appendAuditEvent(req.user.id, { action: 'logout', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    }
    clearSessionCookies(req, res);
    res.json({ ok: true });
  });

  // Authenticated-only to prevent outbound IP discovery by unauthenticated parties.
  // Loopback callers receive the server's outbound public IP (useful on the same host).
  const LOOPBACK_RE_SRV = /^(127\.|::1$|::ffff:127\.)/;
  app.get('/api/my-ip', authMiddleware, requireAuth, async (req, res) => {
    const clientIp = getClientIp(req);
    if (!LOOPBACK_RE_SRV.test(clientIp)) return res.json({ ip: clientIp });
    res.json({ ip: (await getServerPublicIp()) ?? '127.0.0.1' });
  });

  // ── Vault CRUD ─────────────────────────────────────────────────────────────

  function readUserBlob(uid, name, fallback) {
    const filePath = userVaultFile(uid, name);
    const info = userInfo(uid, name);
    if (!existsSync(filePath)) return fallback;
    const raw = readFileSync(filePath);
    // Strict decrypt — throws on AEAD failure, no plaintext fallback.
    const pt = decryptBlob(info, raw);
    return JSON.parse(pt.toString('utf8'));
  }
  async function readUserBlobAsync(uid, name, fallback) {
    const filePath = userVaultFile(uid, name);
    const info = userInfo(uid, name);
    if (!existsSync(filePath)) return fallback;
    const raw = await readFileAsync(filePath);
    const pt = decryptBlob(info, raw);
    return JSON.parse(pt.toString('utf8'));
  }
  function writeUserBlob(uid, name, value) {
    writeEncryptedFile(userVaultFile(uid, name), userInfo(uid, name), value);
  }
  async function writeUserBlobAsync(uid, name, value) {
    return writeEncryptedFileAsync(userVaultFile(uid, name), userInfo(uid, name), value);
  }

  app.get('/api/vault/credentials', authMiddleware, requireAuth, async (req, res) => {
    res.json(await readUserBlobAsync(req.user.id, 'credentials', []));
  });
  app.put('/api/vault/credentials', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    await writeUserBlobAsync(req.user.id, 'credentials', req.body);
    res.json({ ok: true });
  });

  app.get('/api/vault/folders', authMiddleware, requireAuth, async (req, res) => {
    res.json(await readUserBlobAsync(req.user.id, 'folders', []));
  });
  app.put('/api/vault/folders', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    await writeUserBlobAsync(req.user.id, 'folders', req.body);
    res.json({ ok: true });
  });

  app.get('/api/vault/asset-holder', authMiddleware, requireAuth, async (req, res) => {
    res.json(await readUserBlobAsync(req.user.id, 'asset_holder', { emails: [], phoneNumbers: [], u2fKeys: [] }));
  });
  app.put('/api/vault/asset-holder', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    await writeUserBlobAsync(req.user.id, 'asset_holder', req.body);
    res.json({ ok: true });
  });

  app.get('/api/vault/profile', authMiddleware, requireAuth, async (req, res) => {
    res.json(await readUserBlobAsync(req.user.id, 'profile', { firstName: '', lastName: '', email: '' }));
  });
  app.put('/api/vault/profile', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    await writeUserBlobAsync(req.user.id, 'profile', req.body);
    res.json({ ok: true });
  });

  app.get('/api/vault/mfa', authMiddleware, requireAuth, async (req, res) => {
    res.json(await readUserBlobAsync(req.user.id, 'mfa_config', {
      totp: { enabled: false },
      webauthn: { enabled: false, credentials: [] },
      passkey:  { enabled: false, credentials: [] },
      platform: { enabled: false, credentials: [] },
      email:    { enabled: false },
      passwordlessEnabled: false,
    }));
  });
  app.put('/api/vault/mfa', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') {
      return res.status(400).json({ error: 'invalid_input' });
    }
    writeUserBlob(req.user.id, 'mfa_config', req.body);

    // Persist plaintext enforcement flags so the login handler can gate sessions before
    // the session key is available to decrypt the encrypted mfa_config blob.
    // These booleans are NOT secret — only "is TOTP required" / "is email OTP required".
    const { enforce, serverSecret } = req.body;
    const users = loadUsers();
    const idx = users.findIndex(x => x.id === req.user.id);
    if (idx !== -1) {
      if (enforce && typeof enforce === 'object') {
        users[idx].mfaEnforce = {
          totp:  enforce.totp  === true,
          email: enforce.email === true,
        };
      }
      // TOTP secret stored server-encrypted so /login/finish can verify codes
      // without the client session key (which doesn't exist at login time).
      if (typeof serverSecret === 'string' && serverSecret.length > 0) {
        users[idx].mfaTotpSecret = serverSecret;
      } else if (enforce && enforce.totp === false) {
        users[idx].mfaTotpSecret = null; // TOTP disabled — purge the server-held secret
      }
      saveUsers(users);
    }

    appendAuditEvent(req.user.id, { action: 'mfa_changed', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true });
  });

  // SMTP config is provided by the client (stored client-side in encrypted localStorage)
  // so no SMTP credentials are stored on the server.
  app.post('/api/send-expiry-notification', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { smtp, credentials: expiredCreds, toEmail } = req.body ?? {};
    if (
      !smtp?.host || !smtp?.port || !smtp?.username || !smtp?.password ||
      !Array.isArray(expiredCreds) || !toEmail || typeof toEmail !== 'string' ||
      toEmail.length > 320
    ) {
      return res.status(400).json({ error: 'invalid_input' });
    }
    if (expiredCreds.length === 0) return res.json({ ok: true, sent: 0 });

    // Block SSRF to RFC-1918, loopback, and metadata endpoints.
    const smtpHost = String(smtp.host).trim().toLowerCase();
    const BLOCKED_HOST_RE = /^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1|169\.254\.|fd[0-9a-f]{2}:|fc00:)/i;
    if (BLOCKED_HOST_RE.test(smtpHost)) {
      return res.status(400).json({ error: 'invalid_smtp_host' });
    }

    const secure = smtp.protocol === 'ssl_tls';
    const transport = nodemailer.createTransport({
      host: smtpHost,
      port: Number(smtp.port),
      secure,
      auth: { user: String(smtp.username), pass: String(smtp.password) },
    });

    const list = expiredCreds
      .filter(c => c && typeof c.service === 'string')
      .map(c => `• ${c.service} (every ${c.value} ${c.unit})`)
      .join('\n');

    try {
      // `from` is always the authenticated SMTP username — never attacker-controlled.
      await transport.sendMail({
        from: String(smtp.username),
        to: toEmail,
        subject: 'PWDnow — Password Expiry Alert',
        text: `The following credentials in your vault have expired:\n\n${list}\n\nPlease update them at your earliest convenience.`,
      });
      res.json({ ok: true, sent: expiredCreds.length });
    } catch (err) {
      console.error('[expiry-notify]', err.message);
      res.status(502).json({ error: 'smtp_error' });
    }
  });

  // ── Secure Sharing ───────────────────────────────────────────────────────
  // Encrypted blobs stored per-user at vault/<uid>/shares/<id>.json.
  // The share key lives only in the URL fragment — the server never sees it.

  const SHARE_TTL_MS = {
    '1h':  1 * 3600_000,
    '24h': 24 * 3600_000,
    '7d':  7 * 24 * 3600_000,
  };

  app.post('/api/vault/shares', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const { encryptedBlob, iv, ttl, singleView, label } = req.body ?? {};
    if (!encryptedBlob || typeof encryptedBlob !== 'string') return res.status(400).json({ error: 'missing_blob' });
    if (!iv || typeof iv !== 'string') return res.status(400).json({ error: 'missing_iv' });
    const ttlMs = SHARE_TTL_MS[ttl] ?? SHARE_TTL_MS['24h'];
    const uid = req.user.id;
    const sharesDir = userSharesDir(uid);
    if (!existsSync(sharesDir)) mkdirSync(sharesDir, { recursive: true, mode: 0o700 });

    const shareId = randomBytes(16).toString('hex');
    const record = {
      id: shareId,
      label: typeof label === 'string' ? label.slice(0, 100) : '',
      encryptedBlob,
      iv,
      createdAt: Date.now(),
      expiresAt: Date.now() + ttlMs,
      singleView: Boolean(singleView),
      viewed: false,
    };
    const sharePath = path.join(sharesDir, `${shareId}.json`);
    writeFileSync(sharePath, JSON.stringify(record), { mode: 0o600 });
    appendAuditEvent(uid, { action: 'share_created', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, resourceLabel: record.label, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true, shareId });
  });

  app.get('/api/vault/shares', authMiddleware, requireAuth, (req, res) => {
    const sharesDir = userSharesDir(req.user.id);
    if (!existsSync(sharesDir)) return res.json({ ok: true, shares: [] });
    const shares = readdirSync(sharesDir)
      .filter(f => f.endsWith('.json'))
      .map(f => {
        try { return JSON.parse(readFileSync(path.join(sharesDir, f), 'utf8')); } catch { return null; }
      })
      .filter(Boolean)
      .map(({ id, createdAt, expiresAt, singleView, viewed, label }) => ({ id, createdAt, expiresAt, singleView, viewed, label: label || '' }));
    res.json({ ok: true, shares });
  });

  app.delete('/api/vault/shares/:shareId', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const shareId = req.params.shareId;
    if (!/^[0-9a-f]{32}$/.test(shareId)) return res.status(400).json({ error: 'invalid_id' });
    const sharePath = path.join(userSharesDir(req.user.id), `${shareId}.json`);
    let label = '';
    if (existsSync(sharePath)) {
      try { label = JSON.parse(readFileSync(sharePath, 'utf8')).label || ''; } catch { /* ignore */ }
      rmSync(sharePath);
    }
    appendAuditEvent(req.user.id, { action: 'share_revoked', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, resourceLabel: label, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true });
  });

  // Public endpoint — no auth. Rate limited to prevent filesystem enumeration.
  app.get('/api/share/:shareId', async (req, res) => {
    if (!checkEmergencyRate(getClientIp(req))) {
      return res.status(429).json({ error: 'too_many_requests' });
    }
    const { shareId } = req.params;
    if (!/^[0-9a-f]{32}$/.test(shareId)) return res.status(400).json({ error: 'invalid_id' });

    // O(users) scan — acceptable for self-hosted scale.
    const vaultDir = path.join(DATA_DIR, 'vault');
    if (!existsSync(vaultDir)) return res.status(404).json({ error: 'not_found' });

    let recordPath = null;
    for (const uid of readdirSync(vaultDir)) {
      const p = path.join(vaultDir, uid, 'shares', `${shareId}.json`);
      if (existsSync(p)) {
        recordPath = p;
        break;
      }
    }
    if (!recordPath) return res.status(404).json({ error: 'not_found' });

    let release = null;
    let record = null;
    try {
      // Lock enforced (no .catch(()=>null)) to prevent race condition in single-view claim.
      release = await lock(recordPath, { retries: { retries: 10, minTimeout: 100 } });
      if (!existsSync(recordPath)) return res.status(404).json({ error: 'not_found' });
      try { record = JSON.parse(readFileSync(recordPath, 'utf8')); } catch { return res.status(500).json({ error: 'corrupt' }); }

      if (Date.now() > record.expiresAt) {
        try { rmSync(recordPath); } catch { /* ignore */ }
        return res.status(410).json({ error: 'expired' });
      }

      if (record.singleView) {
        if (record.viewed) {
          return res.status(410).json({ error: 'already_viewed' });
        }
        record.viewed = true;
        const tmp = recordPath + '.tmp';
        try {
          writeFileSync(tmp, JSON.stringify(record), { mode: 0o600 });
          renameSync(tmp, recordPath); // atomic rename
        } catch (e) {
          console.error('[share] Atomic update failed:', e.message);
          return res.status(500).json({ error: 'server_error' });
        }
      }
    } finally {
      if (release) await release().catch(() => {});
    }

    res.json({ ok: true, encryptedBlob: record.encryptedBlob, iv: record.iv, expiresAt: record.expiresAt, singleView: record.singleView });
  });

  // ── Emergency Access ─────────────────────────────────────────────────────
  // Config stored per-user at vault/<uid>/emergency.enc; the token in the config
  // is the public URL token (32 hex bytes).

  function emergencyPath(uid) { return userVaultFile(uid, 'emergency'); }
  function emergencyInfo(uid) { return userInfo(uid, 'emergency'); }
  function emergencyRequestsPath(uid) { return userVaultFile(uid, 'emergency_requests'); }
  function emergencyRequestsInfo(uid) { return userInfo(uid, 'emergency_requests'); }

  app.get('/api/vault/emergency', authMiddleware, requireAuth, (req, res) => {
    const cfg = readEncryptedFile(emergencyPath(req.user.id), emergencyInfo(req.user.id), null);
    res.json({ ok: true, config: cfg });
  });

  app.post('/api/vault/emergency', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { contactEmail, waitPeriodHours, password } = req.body || {};
    // #5-FIX: require password re-verification before writing a recovery backdoor (CWE-620).
    if (typeof password !== 'string') return res.status(400).json({ error: 'password_required' });
    if (!contactEmail || typeof contactEmail !== 'string') return res.status(400).json({ error: 'invalid_email' });
    const hours = Number(waitPeriodHours);
    if (![24, 48, 72, 168].includes(hours)) return res.status(400).json({ error: 'invalid_wait_period' });

    const users = loadUsers();
    const u = users.find(x => x.id === req.user.id);
    if (!u) return res.status(401).json({ error: 'user_not_found' });
    if (isMfaLocked(u.id)) return res.status(429).json({ ok: false, error: 'too_many_attempts' });
    const verified = await verifyPassword(u.passwordHash, password, u.salt);
    if (!verified) {
      recordMfaFailure(u.id);
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    clearMfaFailure(u.id);

    const uid = req.user.id;
    if (!existsSync(userVaultDir(uid))) mkdirSync(userVaultDir(uid), { recursive: true, mode: 0o700 });
    const cfg = {
      enabled: true,
      contactEmail: contactEmail.trim().toLowerCase(),
      waitPeriodHours: hours,
      token: randomBytes(32).toString('hex'),
      createdAt: Date.now(),
    };
    writeEncryptedFile(emergencyPath(uid), emergencyInfo(uid), cfg);
    // Never return the token in the creation response — prevents log exposure.
    // The authenticated owner can retrieve it via GET /api/vault/emergency.
    const { token: _stripped, ...safeConfig } = cfg;
    res.json({ ok: true, config: safeConfig });
  });

  app.delete('/api/vault/emergency', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const p = emergencyPath(req.user.id);
    if (existsSync(p)) rmSync(p);
    res.json({ ok: true });
  });

  // Public endpoint — no auth. Rate limited: each call iterates all users + decrypts
  // emergency files, so without limiting this enables cross-tenant DoS.
  app.post('/api/emergency/request/:token', (req, res) => {
    if (!checkEmergencyRate(getClientIp(req))) {
      return res.status(429).json({ error: 'too_many_requests' });
    }
    const { token } = req.params;
    const { requesterName, requesterEmail } = req.body ?? {};
    if (!token || !/^[0-9a-f]{64}$/.test(token)) return res.status(400).json({ error: 'invalid_token' });
    if (!requesterName || typeof requesterName !== 'string') return res.status(400).json({ error: 'invalid_name' });
    if (requesterEmail !== undefined && requesterEmail !== null && requesterEmail !== '') {
      if (typeof requesterEmail !== 'string' || requesterEmail.length > 320 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(requesterEmail)) {
        return res.status(400).json({ error: 'invalid_email' });
      }
    }

    const users = loadUsers();
    let owner = null;
    let ownerCfg = null;
    for (const u of users) {
      const cfg = readEncryptedFile(emergencyPath(u.id), emergencyInfo(u.id), null);
      // Constant-time comparison prevents timing oracle on token prefix.
      const tokenMatch = cfg && cfg.enabled && cfg.token && token &&
        cfg.token.length === token.length &&
        timingSafeEqual(Buffer.from(cfg.token, 'hex'), Buffer.from(token, 'hex'));
      if (tokenMatch) {
        owner = u;
        ownerCfg = cfg;
        break;
      }
    }
    if (!owner) return res.status(404).json({ error: 'not_found' });

    const requests = readEncryptedFile(emergencyRequestsPath(owner.id), emergencyRequestsInfo(owner.id), []);
    const newReq = {
      id: generateUUID(),
      requesterName: requesterName.trim().slice(0, 100),
      requesterEmail: (requesterEmail ?? '').trim().toLowerCase().slice(0, 200),
      requestedAt: Date.now(),
      status: 'pending',
      grantExpiresAt: Date.now() + ownerCfg.waitPeriodHours * 3600_000,
    };
    requests.push(newReq);
    writeEncryptedFile(emergencyRequestsPath(owner.id), emergencyRequestsInfo(owner.id), requests);
    res.json({ ok: true, waitPeriodHours: ownerCfg.waitPeriodHours });
  });

  app.get('/api/vault/emergency/requests', authMiddleware, requireAuth, (req, res) => {
    const requests = readEncryptedFile(emergencyRequestsPath(req.user.id), emergencyRequestsInfo(req.user.id), []);
    res.json({ ok: true, requests });
  });

  app.post('/api/vault/emergency/respond', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const { requestId, action } = req.body ?? {};
    if (!requestId || !['grant', 'deny'].includes(action)) return res.status(400).json({ error: 'invalid_params' });
    const uid = req.user.id;
    const requests = readEncryptedFile(emergencyRequestsPath(uid), emergencyRequestsInfo(uid), []);
    const idx = requests.findIndex(r => r.id === requestId);
    if (idx === -1) return res.status(404).json({ error: 'not_found' });
    requests[idx].status = action === 'grant' ? 'granted' : 'denied';
    requests[idx].respondedAt = Date.now();
    writeEncryptedFile(emergencyRequestsPath(uid), emergencyRequestsInfo(uid), requests);
    res.json({ ok: true });
  });

  // Recursive 3-pass overwrite — covers shares/ subdirectory and any future subdirs.
  function secureOverwriteDir(dir) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      try {
        if (entry.isDirectory()) {
          secureOverwriteDir(p); // recurse
        } else if (entry.isFile()) {
          const size = Math.max(512, Buffer.byteLength(readFileSync(p)));
          for (let i = 0; i < 3; i++) writeFileSync(p, randomBytes(size));
        }
        // Symlinks skipped — do not follow outside the vault dir.
      } catch { /* ignore */ }
    }
  }

  app.post('/api/vault/wipe', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    // #1-FIX: require password re-verification before destructive wipe (CWE-306).
    const { password } = req.body ?? {};
    if (typeof password !== 'string') return res.status(400).json({ error: 'password_required' });
    const users = loadUsers();
    const u = users.find(x => x.id === req.user.id);
    if (!u) return res.status(401).json({ error: 'user_not_found' });
    if (isMfaLocked(u.id)) return res.status(429).json({ ok: false, error: 'too_many_attempts' });
    const verified = await verifyPassword(u.passwordHash, password, u.salt);
    if (!verified) {
      recordMfaFailure(u.id);
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    clearMfaFailure(u.id);

    const dir = userVaultDir(req.user.id);
    if (existsSync(dir)) {
      secureOverwriteDir(dir);
      rmSync(dir, { recursive: true, force: true });
    }
    const remaining = loadUsers().filter(x => x.id !== req.user.id);
    saveUsers(remaining);
    clearSessionCookies(req, res);
    res.json({ ok: true });
  });

  // ── Audit Log ─────────────────────────────────────────────────────────────
  app.get('/api/audit/events', authMiddleware, requireAuth, (req, res) => {
    const limit  = Math.min(Number(req.query.limit)  || 50, 200);
    const offset = Math.max(Number(req.query.offset) || 0,  0);
    const action = req.query.action || null;
    const since  = Number(req.query.since) || 0;
    let events = loadAuditLog(req.user.id);
    if (action) events = events.filter(e => e.action === action);
    if (since)  events = events.filter(e => e.ts >= since);
    events = events.slice().reverse(); // newest first
    res.json({ ok: true, events: events.slice(offset, offset + limit), total: events.length });
  });

  app.delete('/api/audit/events', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    // Require password re-verification with brute-force lockout before clearing logs.
    const { password } = req.body ?? {};
    if (typeof password !== 'string') {
      return res.status(400).json({ error: 'password_required' });
    }
    const users = loadUsers();
    const u = users.find(x => x.id === req.user.id);
    if (!u) return res.status(401).json({ error: 'user_not_found' });

    if (isMfaLocked(u.id)) {
      return res.status(429).json({ ok: false, error: 'too_many_attempts' });
    }

    const verified = await verifyPassword(u.passwordHash, password, u.salt);
    if (!verified) {
      recordMfaFailure(u.id);
      appendAuditEvent(req.user.id, { action: 'audit_clear_rejected', ip: getClientIp(req), success: false });
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    clearMfaFailure(u.id);

    let release = null;
    try {
      const dir = userVaultDir(req.user.id);
      if (existsSync(dir)) {
        release = await lock(dir, { retries: { retries: 10, minTimeout: 100 } });
      }
      // Write a permanent marker before clearing so the next session can detect the gap.
      const marker = { id: generateUUID(), ts: Date.now(), action: 'audit_cleared', ip: getClientIp(req), success: true };
      saveAuditLog(req.user.id, [marker]);
    } finally {
      if (release) await release().catch(() => {});
    }
    res.json({ ok: true });
  });

}
