import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, renameSync, rmSync, readdirSync } from 'fs';
import path from 'path';
import {
  randomBytes,
  timingSafeEqual,
  scryptSync,
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  createHash,
} from 'crypto';
import { EncryptJWT, jwtDecrypt } from 'jose';

// ── Constants ────────────────────────────────────────────────────────────────

const SCRYPT_N = 1 << 17;        // 131072 — OWASP 2023 minimum (~100ms/op on a laptop)
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_LEN = 64;
const SCRYPT_MAXMEM = 256 * 1024 * 1024; // 256 MiB ceiling

const JWE_TTL_SECONDS = 60 * 60 * 24; // 24h absolute
const SESSION_ROLL_SECONDS = 60 * 15; // refresh cookie every 15 min of activity

const COOKIE_SESSION = '_pwd_sess';
const COOKIE_CSRF    = '_pwd_csrf';

// ── Master key ───────────────────────────────────────────────────────────────

let MASTER_KEY = null;
let DATA_DIR = null;

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
}

function derivedKey(info, length = 32) {
  // HKDF-SHA256 key derivation. `info` namespaces each derived key.
  const buf = hkdfSync('sha256', MASTER_KEY, Buffer.alloc(0), Buffer.from(info), length);
  return Buffer.from(buf);
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

// ── User store ───────────────────────────────────────────────────────────────

function usersPath()        { return path.join(DATA_DIR, 'users.enc'); }
function userVaultDir(uid)  { return path.join(DATA_DIR, 'vault', uid); }
function userVaultFile(uid, name) { return path.join(userVaultDir(uid), name + '.enc'); }
function userInfo(uid, name) { return `vault/${uid}/${name}`; }

function loadUsers() {
  return readEncryptedFile(usersPath(), 'users/enc', []);
}
function saveUsers(users) {
  writeEncryptedFile(usersPath(), 'users/enc', users);
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
  if (global.gc) {
    setImmediate(() => global.gc());
  }
  return out.toString('hex');
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
  if (!token) { req.user = null; return next(); }
  const payload = await verifyJwt(token);
  if (!payload) { req.user = null; return next(); }
  const users = loadUsers();
  const u = users.find(x => x.id === payload.sub);
  if (!u) { req.user = null; return next(); }

  // Integrity / Blacklist Check: ensure jti is still active for this user
  const activeSessions = loadSessions(u.id);
  const isActive = activeSessions.some(s => s.jti === payload.jti);
  if (!isActive) { req.user = null; return next(); }

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

function loadSessions(uid) {
  return readEncryptedFile(sessionsPath(uid), userInfo(uid, 'sessions'), []);
}
function saveSessions(uid, list) {
  writeEncryptedFile(sessionsPath(uid), userInfo(uid, 'sessions'), list);
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

function recordSession(uid, jti, req) {
  const { browser: browserHint } = req.body || {};
  const ua = req.headers['user-agent'] || '';
  const ip = getClientIp(req);
  const all = loadSessions(uid).filter(s => s.jti !== jti);
  const updated = all.map(s => ({ ...s, isCurrent: false }));
  
  let deviceName = parseUA(ua);
  if (browserHint && browserHint !== 'Unknown' && deviceName.includes('Chrome')) {
    deviceName = deviceName.replace('Chrome', browserHint);
  }

  updated.push({
    jti,
    id: jti, // use jti as unique id
    timestamp: Date.now(),
    deviceName,
    userAgent:  ua,
    ip:         ip === '::1' || ip === '::ffff:127.0.0.1' ? '127.0.0.1' : ip,
    isCurrent:  true,
  });
  const trimmed = updated.length > 20 ? updated.slice(updated.length - 20) : updated;
  saveSessions(uid, trimmed);
}

// ── Public route mounter ─────────────────────────────────────────────────────

export function mountAuthAndVault(app) {
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
      user: { firstName: profile.firstName, lastName: profile.lastName, email: profile.email, passwordChangedAt: u.passwordChangedAt },
    });
  });

  // POST /api/auth/register
  app.post('/api/auth/register', authMiddleware, async (req, res) => {
    const { email, password, firstName, lastName } = req.body || {};
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

    const salt = randomBytes(16).toString('hex');
    const hash = scryptHash(password, salt);
    const id = randomBytes(16).toString('hex');
    users.push({ id, emailHash, passwordHash: hash, salt, createdAt: Date.now() });
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
    recordSession(id, jti, req);
    res.json({ ok: true });
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
    // Always do the scrypt work to avoid user-enumeration timing leaks.
    const testSalt = u ? u.salt : randomBytes(16).toString('hex');
    const hash = scryptHash(password, testSalt);
    if (!u || !constEq(hash, u.passwordHash)) {
      return res.status(200).json({ ok: false, error: 'invalid_credentials' });
    }
    const { token, jti } = await issueJwt(u.id);
    const csrf = randomBytes(24).toString('hex');
    setSessionCookies(req, res, token, csrf);
    recordSession(u.id, jti, req);
    res.json({ ok: true });
  });

  // POST /api/auth/verify-password — verify current password without changing it
  app.post('/api/auth/verify-password', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { password } = req.body || {};
    if (typeof password !== 'string') return res.status(400).json({ error: 'invalid_input' });
    const users = loadUsers();
    const u = users.find(x => x.id === req.user.id);
    if (!u) return res.status(401).json({ error: 'user_not_found' });
    const hash = scryptHash(password, u.salt);
    if (!constEq(hash, u.passwordHash)) {
      return res.json({ ok: false });
    }
    res.json({ ok: true });
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
    const hash = scryptHash(oldPassword, u.salt);
    if (!constEq(hash, u.passwordHash)) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    const newSalt = randomBytes(16).toString('hex');
    const newHash = scryptHash(newPassword, newSalt);
    users[uIndex].salt = newSalt;
    users[uIndex].passwordHash = newHash;
    users[uIndex].passwordChangedAt = Date.now();
    saveUsers(users);

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
    }
    clearSessionCookies(req, res);
    res.json({ ok: true });
  });

  // ── Vault CRUD ─────────────────────────────────────────────────────────────

  function readUserBlob(uid, name, fallback) {
    return readEncryptedFile(userVaultFile(uid, name), userInfo(uid, name), fallback);
  }
  function writeUserBlob(uid, name, value) {
    writeEncryptedFile(userVaultFile(uid, name), userInfo(uid, name), value);
  }

  // Credentials (full list)
  app.get('/api/vault/credentials', authMiddleware, requireAuth, (req, res) => {
    res.json(readUserBlob(req.user.id, 'credentials', []));
  });
  app.put('/api/vault/credentials', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    if (!Array.isArray(req.body)) return res.status(400).json({ error: 'invalid_input' });
    writeUserBlob(req.user.id, 'credentials', req.body);
    res.json({ ok: true });
  });

  // Folders
  app.get('/api/vault/folders', authMiddleware, requireAuth, (req, res) => {
    res.json(readUserBlob(req.user.id, 'folders', []));
  });
  app.put('/api/vault/folders', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    if (!Array.isArray(req.body)) return res.status(400).json({ error: 'invalid_input' });
    writeUserBlob(req.user.id, 'folders', req.body);
    res.json({ ok: true });
  });

  // Asset holder
  app.get('/api/vault/asset-holder', authMiddleware, requireAuth, (req, res) => {
    res.json(readUserBlob(req.user.id, 'asset_holder', { emails: [], phoneNumbers: [], u2fKeys: [] }));
  });
  app.put('/api/vault/asset-holder', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const b = req.body || {};
    if (!Array.isArray(b.emails) || !Array.isArray(b.phoneNumbers) || !Array.isArray(b.u2fKeys)) {
      return res.status(400).json({ error: 'invalid_input' });
    }
    writeUserBlob(req.user.id, 'asset_holder', b);
    res.json({ ok: true });
  });

  // Profile
  app.get('/api/vault/profile', authMiddleware, requireAuth, (req, res) => {
    res.json(readUserBlob(req.user.id, 'profile', { firstName: '', lastName: '', email: '' }));
  });
  app.put('/api/vault/profile', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const b = req.body || {};
    if (typeof b.firstName !== 'string' || typeof b.lastName !== 'string' || typeof b.email !== 'string') {
      return res.status(400).json({ error: 'invalid_input' });
    }
    writeUserBlob(req.user.id, 'profile', b);
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
}
