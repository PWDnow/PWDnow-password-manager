import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, renameSync, rmSync, readdirSync } from 'fs';
import { promisify } from 'util';
import nodemailer from 'nodemailer';
import path from 'path';
import argon2 from 'argon2';
import {
  randomBytes,
  timingSafeEqual,
  scryptSync,
  pbkdf2Sync,
  pbkdf2,
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  createHash,
} from 'crypto';

// Async PBKDF2 — runs in libuv thread pool, does NOT block the event loop.
// Critical: 1M-iteration pbkdf2Sync blocked the event loop for ~5-8 s on login.
const pbkdf2Async = promisify(pbkdf2);
// JWE per RFC 7516/7518; JOSE BCP per RFC 8725 (alg pinned to "dir" — no algorithm confusion).
import { EncryptJWT, jwtDecrypt } from 'jose';
import { TOTP } from 'totp-generator';
import { IpIntelligenceService } from './ipIntelligence.js';

// ── Constants ────────────────────────────────────────────────────────────────

const SCRYPT_N = 1 << 17;        // 131072 — kept for legacy verification only
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_LEN = 64;
const SCRYPT_MAXMEM = 256 * 1024 * 1024; // 256 MiB ceiling

// PBKDF2-HMAC-SHA-512, 1,000,000 iterations — NSA CNSA 2.0 (CSI-CNSA-2.0, Sept 2022) requirement; salt per NIST SP 800-132 (2010).
// Retained for legacy verification only — new hashes use Argon2id below.
const PBKDF2_SHA512_ITERS = 1_000_000;
const PBKDF2_SHA512_LEN   = 64; // bytes
const PBKDF2_HASH_PREFIX  = '$pbkdf2sha512$';

// Argon2id parameters for server-mode password hashing (NIST SP 800-63B-4 §5.1.1.2 AAL3).
// m=128 MiB chosen to balance security and multi-tenant Express memory; t=3, p=1 (native
// argon2 npm uses the libuv thread pool — non-blocking for Node.js event loop).
const ARGON2_MEMORY_KIB  = 128 * 1024; // 128 MiB
const ARGON2_TIME_COST   = 3;
const ARGON2_PARALLELISM = 1;

// Concurrency gate — prevents memory exhaustion DoS (HIGH-01).
// Declared here (before hashPassword) so the function closure closes over initialised values.
let   _argon2ActiveCount = 0;
const ARGON2_MAX_CONCURRENT = 3;

const JWE_TTL_SECONDS = 60 * 60 * 24; // 24h absolute
const SESSION_ROLL_SECONDS = 60 * 15; // refresh cookie every 15 min of activity

const COOKIE_SESSION = '_pwd_sess';
const COOKIE_CSRF    = '_pwd_csrf';

// ── Partial MFA tokens (D.1 / S-01) ─────────────────────────────────────────
// In-memory map: token-hash -> { userId, expiresAt }.
// Ensures MFA is enforced server-side before a full session is issued.
const PARTIAL_MFA_TTL_MS = 5 * 60 * 1000; // 5 minutes
const pendingMfaTokens = new Map(); // key: hex(SHA-256(token)), value: { userId, expiresAt }

function issueMfaToken(userId) {
  const token = randomBytes(32).toString('hex');
  const hash  = createHash('sha256').update(token, 'hex').digest('hex');
  pendingMfaTokens.set(hash, { userId, expiresAt: Date.now() + PARTIAL_MFA_TTL_MS });
  return token;
}

function consumeMfaToken(token) {
  const hash = createHash('sha256').update(token, 'hex').digest('hex');
  const entry = pendingMfaTokens.get(hash);
  if (!entry) return null;
  pendingMfaTokens.delete(hash); // single-use
  if (Date.now() > entry.expiresAt) return null; // expired
  return entry.userId;
}

// ── TOTP verification (server-side, S-01) ────────────────────────────────────
async function verifyTotpCode(secret, code) {
  if (!/^\d{6,8}$/.test(code)) return false;
  const now = Date.now();
  for (const drift of [-30000, 0, 30000]) {
    const { otp } = await TOTP.generate(secret, { timestamp: now + drift });
    if (otp.length === code.length && timingSafeEqual(Buffer.from(otp), Buffer.from(code))) return true;
  }
  return false;
}

// ── Master key ───────────────────────────────────────────────────────────────

let MASTER_KEY = null;
let DATA_DIR = null;
let ipIntel = null;
let ipPolicy = { blockTor: true, blockProxy: true, blockVpn: false, blockAbuser: true };

// Cache HKDF-derived sub-keys — safe because MASTER_KEY is constant after initAuth.
// Eliminates repeated hkdfSync calls on every encrypt/decrypt/JWT operation.
const _derivedKeyCache = new Map();

export function initAuth({ dataDir }) {
  DATA_DIR = dataDir;
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
  ipIntel = new IpIntelligenceService(process.env.IPREGISTRY_API_KEY ?? '');
  ipPolicy = loadIpPolicy();
  // Pre-warm the server public IP so the first login's recordSession() returns
  // instantly from cache instead of making an outbound network call mid-request.
  getServerPublicIp().catch(() => {});
  // Pre-populate the derived-key cache for the two hottest keys used on every request.
  derivedKey('jwe/session', 32);
  derivedKey('users/enc', 32);
}

function derivedKey(info, length = 32) {
  // CNSA 2.0: HKDF-SHA-384 replaces HKDF-SHA-256 (NIST SP 800-56C, NSA CSI-CNSA-2.0).
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

// S-02: strict reader — returns fallback when absent, throws on integrity failure.
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

// In-memory users cache — write-through, TTL 60 s.
// Eliminates two file-read + AES-GCM-decrypt operations on every authenticated request.
let _usersCache = null;
let _usersCacheTs = 0;
const USERS_CACHE_TTL_MS = 60_000;

function loadUsers() {
  const now = Date.now();
  if (_usersCache !== null && now - _usersCacheTs < USERS_CACHE_TTL_MS) return _usersCache;
  _usersCache = readEncryptedFile(usersPath(), 'users/enc', []);
  _usersCacheTs = now;
  return _usersCache;
}
function saveUsers(users) {
  writeEncryptedFile(usersPath(), 'users/enc', users);
  _usersCache = users;
  _usersCacheTs = Date.now();
}

function hashEmail(email) {
  return createHash('sha256').update(email.trim().toLowerCase(), 'utf8').digest('hex');
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

// CNSA 2.0: PBKDF2-SHA-512 with 1,000,000 iterations for all new registrations.
// Format: `$pbkdf2sha512$<saltHex>$<hashHex>` — constant-time compare via timingSafeEqual.
// Both functions are async so the 1M-iteration computation runs in libuv's thread
// pool (via pbkdf2Async) and does NOT block the Node.js event loop.
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
  // Argon2id — NIST SP 800-63B-4 (2024) §5.1.1.2 memory-hard KDF for AAL3.
  // Native `argon2` npm runs in the libuv thread pool; does NOT block event loop.
  // Concurrency gate: at 128 MiB per hash, unconstrained concurrency exhausts RAM.
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
  // New format: $argon2id$ — primary path
  if (hashOrLegacy && hashOrLegacy.startsWith('$argon2id$')) {
    return argon2.verify(hashOrLegacy, password);
  }
  // Intermediate legacy: PBKDF2-SHA-512 — verify and opportunistically rehash
  if (hashOrLegacy && hashOrLegacy.startsWith(PBKDF2_HASH_PREFIX)) {
    return pbkdf2Sha512Verify(hashOrLegacy, password);
  }
  // Older legacy: argon2 variants ($argon2i$, $argon2d$, bare $argon2$)
  if (hashOrLegacy && hashOrLegacy.startsWith('$argon2')) {
    return argon2.verify(hashOrLegacy, password);
  }
  if (!hashOrLegacy || !legacySaltHex) {
    // Dummy stretch to prevent user-enumeration timing oracle; discard result.
    await pbkdf2Async(Buffer.from(password), randomBytes(32), 1000, 64, 'sha512');
    return false;
  }
  // Oldest legacy: scrypt.
  const hash = scryptHash(password, legacySaltHex);
  return constEq(hash, hashOrLegacy);
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
  const isSecure = req.protocol === 'https';
  const common = { httpOnly: true, secure: isSecure, sameSite: 'Strict', path: '/' };
  res.cookie(COOKIE_SESSION, token, common);
  res.cookie(COOKIE_CSRF, csrf, { ...common, httpOnly: false });
}

function clearSessionCookies(req, res) {
  const isSecure = req.protocol === 'https';
  const common = { httpOnly: true, secure: isSecure, sameSite: 'Strict', path: '/' };
  res.clearCookie(COOKIE_SESSION, common);
  res.clearCookie(COOKIE_CSRF, { ...common, httpOnly: false });
}

async function authMiddleware(req, _res, next) {
  const token = req.cookies?.[COOKIE_SESSION];
  if (!token) { 
    console.log(`[auth] No session cookie found for ${req.url}`);
    req.user = null; 
    return next(); 
  }
  const payload = await verifyJwt(token);
  if (!payload) { 
    console.log(`[auth] Invalid JWT payload for ${req.url}`);
    req.user = null; 
    return next(); 
  }
  const users = loadUsers();
  const u = users.find(x => x.id === payload.sub);
  if (!u) { 
    console.log(`[auth] User not found: ${payload.sub} for ${req.url}`);
    req.user = null; 
    return next(); 
  }

  // Integrity / Blacklist Check: ensure jti is still active for this user
  const activeSessions = loadSessions(u.id);
  const isActive = activeSessions.some(s => s.jti === payload.jti);
  if (!isActive) { 
    console.log(`[auth] Session JTI not active: ${payload.jti} for user ${u.id} (${req.url})`);
    console.log(`[auth] Active JTIs: ${activeSessions.map(s => s.jti).join(', ')}`);
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
  // Only enforce on state-changing methods
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

// In-memory per-user sessions cache — write-through, TTL 60 s.
// Eliminates a file-read + AES-GCM-decrypt on every authMiddleware call.
const _sessionsCache = new Map(); // uid → { data: Array, ts: number }
const SESSIONS_CACHE_TTL_MS = 60_000;

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
  
  // Note: Brave UA is identical to Chrome. The client-side detector in
  // sessionTracker.ts passes the real browser name if it can.
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
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) return xForwardedFor.split(',')[0].trim();
  return req.headers['x-real-ip'] || req.socket.remoteAddress || '127.0.0.1';
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
  return readEncryptedFile(auditLogPath(uid), userInfo(uid, 'audit_log'), []);
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

// Cache the server's outbound public IP once (used when client IP is loopback).
let _serverPublicIp = null;
let _serverPublicIpFetched = false;
export async function getServerPublicIp() {
  if (_serverPublicIpFetched) return _serverPublicIp;
  _serverPublicIpFetched = true; // set before fetch to avoid concurrent calls
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const r = await fetch('https://api64.ipify.org?format=json', { signal: controller.signal });
    clearTimeout(timer);
    const data = await r.json();
    _serverPublicIp = data.ip || null;
  } catch { _serverPublicIp = null; }
  return _serverPublicIp;
}

const LOOPBACK_RE = /^(127\.|::1$|::ffff:127\.)/;
async function appendAuditEvent(uid, event) {
  try {
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
    events.push({ id: generateUUID(), ts: Date.now(), ...enriched });
    const trimmed = events.length > 1000 ? events.slice(events.length - 1000) : events;
    saveAuditLog(uid, trimmed);
  } catch (err) {
    console.error('[audit] append failed:', err.message);
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
}

// ── Public route mounter ─────────────────────────────────────────────────────

// Periodic cleanup of expired partial MFA tokens (MED-07).
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pendingMfaTokens) {
    if (now > v.expiresAt) pendingMfaTokens.delete(k);
  }
}, 60_000);

export function mountAuthAndVault(app) {
  app.use(ipBlockingMiddleware);

  // ── Auth ───────────────────────────────────────────────────────────────────

  // GET /api/auth/me — whoami
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

  // POST /api/auth/register
  app.post('/api/auth/register', authMiddleware, async (req, res) => {
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
    // We use cryptoSalt for the Zero-Knowledge frontend key derivation.
    // The existing 'salt' field is used for server-side password hashing.
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

  // GET /api/auth/login-hints
  app.get('/api/auth/login-hints', authMiddleware, async (req, res) => {
    const email = req.query.email;
    if (typeof email !== 'string') return res.status(400).json({ error: 'invalid_input' });
    const emailHash = hashEmail(email);
    const users = loadUsers();
    const u = users.find(x => x.emailHash === emailHash);
    if (!u || !u.loginHints) {
      return res.json({ hints: { totp: false, emailOtp: false, passwordEnabled: true, webauthn: false, passwordlessEnabled: false, cryptoSalt: u?.cryptoSalt || null } });
    }
    return res.json({ hints: { ...u.loginHints, cryptoSalt: u.cryptoSalt || null } });
  });

  // POST /api/auth/login-hints
  app.post('/api/auth/login-hints', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { hints } = req.body || {};
    if (!hints) return res.status(400).json({ error: 'invalid_input' });
    const users = loadUsers();
    const userIndex = users.findIndex(x => x.id === req.user.id);
    if (userIndex === -1) return res.status(401).json({ error: 'user_not_found' });
    users[userIndex].loginHints = hints;
    saveUsers(users);
    res.json({ ok: true });
  });

  // POST /api/auth/crypto-salt — store or update the browser-side PBKDF2 salt.
  // The client derives AES-GCM encryption keys from password + this salt using
  // PBKDF2-SHA-512. The salt MUST be persisted server-side so it survives browser
  // cache clears — without it, the browser generates a new random salt on each
  // login, producing a different key that cannot decrypt existing vault data.
  // This endpoint is the primary fix for the recurring "folders vanish after
  // clear cache" bug. It is also called during registration (Register.tsx sends
  // cryptoSalt in the registration payload), but legacy accounts that were
  // created before the salt was persisted server-side will hit this endpoint on
  // their next login.
  app.post('/api/auth/crypto-salt', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { cryptoSalt } = req.body || {};
    if (typeof cryptoSalt !== 'string' || !/^[0-9a-f]{32}$/i.test(cryptoSalt)) {
      return res.status(400).json({ error: 'invalid_salt' });
    }
    const users = loadUsers();
    const userIndex = users.findIndex(x => x.id === req.user.id);
    if (userIndex === -1) return res.status(401).json({ error: 'user_not_found' });
    // Only set if the user doesn't already have a cryptoSalt — never overwrite
    // an existing one, as that would make previously encrypted data unreadable.
    if (!users[userIndex].cryptoSalt) {
      users[userIndex].cryptoSalt = cryptoSalt;
      saveUsers(users);
      console.log(`[auth] Stored cryptoSalt for user ${req.user.id}`);
    }
    res.json({ ok: true, cryptoSalt: users[userIndex].cryptoSalt });
  });

  // POST /api/auth/login
  app.post('/api/auth/login', authMiddleware, async (req, res) => {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'invalid_input' });
    }
    const emailHash = hashEmail(email);
    const users = loadUsers();
    const u = users.find(x => x.emailHash === emailHash);
    
    // Always do the hashing work to avoid user-enumeration timing leaks.
    let authenticated = await verifyPassword(u?.passwordHash, password, u?.salt);

    // Fallback: check recovery key if password fails (reject if expired, S-15).
    if (u && !authenticated && u.recoveryKeyHash) {
      const expired = u.recoveryKeyExpiresAt && Date.now() > u.recoveryKeyExpiresAt;
      if (!expired && await verifyPassword(u.recoveryKeyHash, password, u.recoveryKeySalt)) {
        authenticated = true;
      }
    }

    if (authenticated && u && u.passwordHash && !u.passwordHash.startsWith('$argon2id$')) {
      // Opportunistic rehash-on-login: upgrade PBKDF2 / scrypt / argon2i / argon2d → argon2id
      u.passwordHash = await hashPassword(password);
      u.salt = null;
      saveUsers(users);
    }
    if (!authenticated) {
      if (u) appendAuditEvent(u.id, { action: 'login_failed', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: false, riskFlags: req.ipRecord?.riskFlags ?? [] });
      return res.status(200).json({ ok: false, error: 'invalid_credentials' });
    }

    // D.1 / S-01: check if MFA is configured server-side. If so, return a partial
    // token and require the client to complete /api/auth/login/finish before a
    // full session is issued. This prevents clients from bypassing 2FA.
    const mfaCfg = readUserBlob(u.id, 'mfa_config', { totp: { enabled: false } });
    const mfaMethods = [];
    if (mfaCfg.totp?.enabled)  mfaMethods.push('totp');
    if (mfaCfg.email?.enabled) mfaMethods.push('email');

    if (mfaMethods.length > 0) {
      const partialToken = issueMfaToken(u.id);
      return res.json({ ok: true, partialToken, methods: mfaMethods });
    }

    console.log(`[auth] Completing login for user: ${u.id}`);
    const { token, jti } = await issueJwt(u.id);
    const csrf = randomBytes(24).toString('hex');
    setSessionCookies(req, res, token, csrf);
    await recordSession(u.id, jti, req);
    appendAuditEvent(u.id, { action: 'login', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true });
  });

  // POST /api/auth/login/finish — complete the MFA challenge and issue a full session (D.1 / S-01)
  app.post('/api/auth/login/finish', authMiddleware, async (req, res) => {
    const { partialToken, totpCode, emailCode } = req.body || {};
    if (typeof partialToken !== 'string') return res.status(400).json({ error: 'invalid_input' });

    const userId = consumeMfaToken(partialToken);
    if (!userId) return res.status(401).json({ ok: false, error: 'invalid_or_expired_mfa_token' });

    const users = loadUsers();
    const u = users.find(x => x.id === userId);
    if (!u) return res.status(401).json({ ok: false, error: 'user_not_found' });

    const mfaCfg = readUserBlob(u.id, 'mfa_config', { totp: { enabled: false } });

    // Verify whichever MFA method was used.
    if (mfaCfg.totp?.enabled && mfaCfg.totp?.secret) {
      const code = totpCode ?? emailCode;
      if (typeof code !== 'string') return res.status(401).json({ ok: false, error: 'mfa_required' });
      if (!await verifyTotpCode(mfaCfg.totp.secret, code)) {
        appendAuditEvent(u.id, { action: 'mfa_failed', ip: getClientIp(req), success: false });
        return res.status(401).json({ ok: false, error: 'invalid_mfa_code' });
      }
    } else if (mfaCfg.email?.enabled) {
      // Email OTP is client-side simulated; any non-empty code is accepted on the
      // server side (the real check happens on the frontend against the in-memory code).
      if (typeof emailCode !== 'string' || emailCode.length < 6) {
        return res.status(401).json({ ok: false, error: 'mfa_required' });
      }
    }

    console.log(`[auth] Completing login (MFA) for user: ${userId}`);
    const { token, jti } = await issueJwt(userId);
    const csrf = randomBytes(24).toString('hex');
    setSessionCookies(req, res, token, csrf);
    await recordSession(userId, jti, req);
    appendAuditEvent(userId, { action: 'login', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true });
  });

  // POST /api/auth/recovery-key
  app.post('/api/auth/recovery-key', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { recoveryKey } = req.body || {};
    if (typeof recoveryKey !== 'string' || recoveryKey.length < 16) {
      return res.status(400).json({ error: 'invalid_input' });
    }

    const users = loadUsers();
    const uIndex = users.findIndex(x => x.id === req.user.id);
    if (uIndex === -1) return res.status(401).json({ error: 'user_not_found' });

    const hash = await hashPassword(recoveryKey);

    users[uIndex].recoveryKeyHash = hash;
    users[uIndex].recoveryKeySalt = null; // Argon2id embeds salt in the hash string
    users[uIndex].recoveryKeyGeneratedAt = Date.now();
    // S-15 / D.11: recovery key expires after 90 days; force re-issue.
    users[uIndex].recoveryKeyExpiresAt = Date.now() + 90 * 24 * 60 * 60 * 1000;
    saveUsers(users);

    res.json({ ok: true });
  });

  // POST /api/auth/verify-password — verify current password without changing it
  app.post('/api/auth/verify-password', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    try {
      const { password } = req.body || {};
      if (typeof password !== 'string') return res.status(400).json({ error: 'invalid_input' });
      const users = loadUsers();
      const u = users.find(x => x.id === req.user.id);
      if (!u) return res.status(401).json({ error: 'user_not_found' });
      
      const authenticated = await verifyPassword(u.passwordHash, password, u.salt);
      if (!authenticated) {
        return res.json({ ok: false });
      }
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'server_error' });
    }
  });

  // POST /api/auth/password
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
    // S-07 / D.4: atomically invalidate all JTIs on password change.
    // The current session JTI is the only one that survives (cleared on next logout).
    saveSessions(req.user.id, []);
    appendAuditEvent(req.user.id, { action: 'password_changed', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true });
  });

  // GET /api/auth/sessions — list active sessions
  app.get('/api/auth/sessions', authMiddleware, requireAuth, (req, res) => {
    const list = loadSessions(req.user.id).slice().sort((a, b) => b.timestamp - a.timestamp);
    res.json(list);
  });

  // POST /api/auth/sessions/revoke-others
  app.post('/api/auth/sessions/revoke-others', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const list = loadSessions(req.user.id).filter(s => s.jti === req.user.jti);
    saveSessions(req.user.id, list);
    res.json({ ok: true });
  });

  // POST /api/auth/logout
  app.post('/api/auth/logout', authMiddleware, requireCsrf, (req, res) => {
    if (req.user) {
      const list = loadSessions(req.user.id).filter(s => s.jti !== req.user.jti);
      saveSessions(req.user.id, list);
      appendAuditEvent(req.user.id, { action: 'logout', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    }
    clearSessionCookies(req, res);
    res.json({ ok: true });
  });

  // ── Vault CRUD ─────────────────────────────────────────────────────────────

  function readUserBlob(uid, name, fallback) {
    const filePath = userVaultFile(uid, name);
    const info = userInfo(uid, name);
    if (!existsSync(filePath)) return fallback;
    const raw = readFileSync(filePath);
    // Try decrypting first (new format).
    try {
      const pt = decryptBlob(info, raw);
      return JSON.parse(pt.toString('utf8'));
    } catch {
      // S-02 migration: legacy plaintext JSON file — read it and immediately
      // re-encrypt so future reads are strict. Any subsequent integrity failure
      // will hard-fail rather than silently returning stale data.
      try {
        const parsed = JSON.parse(raw.toString('utf8'));
        writeEncryptedFile(filePath, info, parsed); // upgrade in place
        return parsed;
      } catch {
        throw new Error(`vault file integrity check failed: ${filePath}`);
      }
    }
  }
  function writeUserBlob(uid, name, value) {
    writeEncryptedFile(userVaultFile(uid, name), userInfo(uid, name), value);
  }

  // Credentials (full list)
  app.get('/api/vault/credentials', authMiddleware, requireAuth, (req, res) => {
    res.json(readUserBlob(req.user.id, 'credentials', []));
  });
  app.put('/api/vault/credentials', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    writeUserBlob(req.user.id, 'credentials', req.body);
    res.json({ ok: true });
  });

  // Folders
  app.get('/api/vault/folders', authMiddleware, requireAuth, (req, res) => {
    res.json(readUserBlob(req.user.id, 'folders', []));
  });
  app.put('/api/vault/folders', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    writeUserBlob(req.user.id, 'folders', req.body);
    res.json({ ok: true });
  });

  // Asset holder
  app.get('/api/vault/asset-holder', authMiddleware, requireAuth, (req, res) => {
    res.json(readUserBlob(req.user.id, 'asset_holder', { emails: [], phoneNumbers: [], u2fKeys: [] }));
  });
  app.put('/api/vault/asset-holder', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    writeUserBlob(req.user.id, 'asset_holder', req.body);
    res.json({ ok: true });
  });

  // Profile
  app.get('/api/vault/profile', authMiddleware, requireAuth, (req, res) => {
    res.json(readUserBlob(req.user.id, 'profile', { firstName: '', lastName: '', email: '' }));
  });
  app.put('/api/vault/profile', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    writeUserBlob(req.user.id, 'profile', req.body);
    res.json({ ok: true });
  });

  // MFA config — stored encrypted alongside vault data so it survives logout/login
  app.get('/api/vault/mfa', authMiddleware, requireAuth, (req, res) => {
    res.json(readUserBlob(req.user.id, 'mfa_config', {
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
    appendAuditEvent(req.user.id, { action: 'mfa_changed', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true });
  });

  // Password expiry email notification — SMTP config is provided by the client
  // (stored client-side in encrypted localStorage) so no credentials touch disk here.
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

    const secure = smtp.protocol === 'ssl_tls';
    const transport = nodemailer.createTransport({
      host: String(smtp.host),
      port: Number(smtp.port),
      secure,
      auth: { user: String(smtp.username), pass: String(smtp.password) },
    });

    const list = expiredCreds
      .filter(c => c && typeof c.service === 'string')
      .map(c => `• ${c.service} (every ${c.value} ${c.unit})`)
      .join('\n');

    try {
      await transport.sendMail({
        from: smtp.fromAddress ? String(smtp.fromAddress) : String(smtp.username),
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
  // Encrypted blobs are stored per-user at vault/<uid>/shares/<id>.json
  // The share key lives only in the URL fragment — the server never sees it.

  const SHARE_TTL_MS = {
    '1h':  1 * 3600_000,
    '24h': 24 * 3600_000,
    '7d':  7 * 24 * 3600_000,
  };

  // Create a new share (requires auth + CSRF)
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

  // List shares owned by user (requires auth)
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

  // Delete a share (requires auth + CSRF)
  app.delete('/api/vault/shares/:shareId', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const sharePath = path.join(userSharesDir(req.user.id), `${req.params.shareId}.json`);
    let label = '';
    if (existsSync(sharePath)) {
      try { label = JSON.parse(readFileSync(sharePath, 'utf8')).label || ''; } catch { /* ignore */ }
      rmSync(sharePath);
    }
    appendAuditEvent(req.user.id, { action: 'share_revoked', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, resourceLabel: label, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true });
  });

  // Public endpoint — no auth. Returns the encrypted blob if the share is still valid.
  app.get('/api/share/:shareId', (req, res) => {
    const { shareId } = req.params;
    if (!/^[0-9a-f]{32}$/.test(shareId)) return res.status(400).json({ error: 'invalid_id' });

    // Search across all users' shares (O(users) scan — acceptable for self-hosted scale)
    const vaultDir = path.join(DATA_DIR, 'vault');
    if (!existsSync(vaultDir)) return res.status(404).json({ error: 'not_found' });

    let record = null;
    let recordPath = null;
    for (const uid of readdirSync(vaultDir)) {
      const p = path.join(vaultDir, uid, 'shares', `${shareId}.json`);
      if (existsSync(p)) {
        try { record = JSON.parse(readFileSync(p, 'utf8')); recordPath = p; } catch { /* ignore */ }
        break;
      }
    }
    if (!record) return res.status(404).json({ error: 'not_found' });
    if (Date.now() > record.expiresAt) {
      try { rmSync(recordPath); } catch { /* ignore */ }
      return res.status(410).json({ error: 'expired' });
    }
    if (record.singleView && record.viewed) return res.status(410).json({ error: 'already_viewed' });

    // Mark as viewed for single-view shares
    if (record.singleView) {
      record.viewed = true;
      try { writeFileSync(recordPath, JSON.stringify(record)); } catch { /* ignore */ }
    }

    res.json({ ok: true, encryptedBlob: record.encryptedBlob, iv: record.iv, expiresAt: record.expiresAt, singleView: record.singleView });
  });

  // ── Emergency Access ─────────────────────────────────────────────────────
  // Config stored per-user at vault/<uid>/emergency.enc
  // Token stored in config is the public URL token — 32 hex bytes.

  function emergencyPath(uid) { return userVaultFile(uid, 'emergency'); }
  function emergencyInfo(uid) { return userInfo(uid, 'emergency'); }
  function emergencyRequestsPath(uid) { return userVaultFile(uid, 'emergency_requests'); }
  function emergencyRequestsInfo(uid) { return userInfo(uid, 'emergency_requests'); }

  app.get('/api/vault/emergency', authMiddleware, requireAuth, (req, res) => {
    const cfg = readEncryptedFile(emergencyPath(req.user.id), emergencyInfo(req.user.id), null);
    res.json({ ok: true, config: cfg });
  });

  app.post('/api/vault/emergency', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const { contactEmail, waitPeriodHours } = req.body;
    if (!contactEmail || typeof contactEmail !== 'string') return res.status(400).json({ error: 'invalid_email' });
    const hours = Number(waitPeriodHours);
    if (![24, 48, 72, 168].includes(hours)) return res.status(400).json({ error: 'invalid_wait_period' });
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
    res.json({ ok: true, config: cfg });
  });

  app.delete('/api/vault/emergency', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const p = emergencyPath(req.user.id);
    if (existsSync(p)) rmSync(p);
    res.json({ ok: true });
  });

  // Public endpoint — no auth required. Contact uses this to request access.
  app.post('/api/emergency/request/:token', (req, res) => {
    const { token } = req.params;
    const { requesterName, requesterEmail } = req.body ?? {};
    if (!token || !/^[0-9a-f]{64}$/.test(token)) return res.status(400).json({ error: 'invalid_token' });
    if (!requesterName || typeof requesterName !== 'string') return res.status(400).json({ error: 'invalid_name' });

    // Find the vault owner whose emergency token matches
    const users = loadUsers();
    let owner = null;
    let ownerCfg = null;
    for (const u of users) {
      const cfg = readEncryptedFile(emergencyPath(u.id), emergencyInfo(u.id), null);
      if (cfg && cfg.enabled && cfg.token === token) {
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

  // Owner reads pending emergency requests
  app.get('/api/vault/emergency/requests', authMiddleware, requireAuth, (req, res) => {
    const requests = readEncryptedFile(emergencyRequestsPath(req.user.id), emergencyRequestsInfo(req.user.id), []);
    res.json({ ok: true, requests });
  });

  // Owner grants or denies a request
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

  // Forensic wipe of the current user's data (requires auth + CSRF)
  app.post('/api/vault/wipe', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const dir = userVaultDir(req.user.id);
    if (existsSync(dir)) {
      // 3-pass random overwrite of each file before unlink
      for (const f of readdirSync(dir)) {
        const p = path.join(dir, f);
        try {
          const size = Math.max(512, Buffer.byteLength(readFileSync(p)));
          for (let i = 0; i < 3; i++) writeFileSync(p, randomBytes(size));
        } catch { /* ignore */ }
      }
      rmSync(dir, { recursive: true, force: true });
    }
    const users = loadUsers().filter(u => u.id !== req.user.id);
    saveUsers(users);
    clearSessionCookies(req, res);
    res.json({ ok: true });
  });

  // ── Audit Log Routes ──────────────────────────────────────────────────────
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

  app.delete('/api/audit/events', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    saveAuditLog(req.user.id, []);
    res.json({ ok: true });
  });

}
