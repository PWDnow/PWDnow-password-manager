import { randomBytes, createHash, timingSafeEqual } from 'crypto';
import { EncryptJWT, jwtDecrypt } from 'jose';
import { existsSync } from 'fs';
import { lock } from 'proper-lockfile';
import path from 'path';
import { ctx } from './context.js';
import {
  derivedKey,
  userVaultDir,
  userInfo,
  readEncryptedFile,
  writeEncryptedFile,
  loadUsers,
} from './fileCrypto.js';

// ── Constants ─────────────────────────────────────────────────────────────────

export const JWE_TTL_SECONDS    = 60 * 60 * 24; // 24h absolute
export const SESSION_ROLL_SECONDS = 60 * 15;      // refresh cookie every 15 min of activity

export const COOKIE_SESSION = '_pwd_sess';
export const COOKIE_CSRF    = '_pwd_csrf';

// ── JWT / JWE ─────────────────────────────────────────────────────────────────

export async function issueJwt(userId) {
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

export async function verifyJwt(token) {
  try {
    const secret = derivedKey('jwe/session');
    const { payload } = await jwtDecrypt(token, secret);
    return payload;
  } catch {
    return null;
  }
}

export function setSessionCookies(req, res, token, csrf) {
  const isSecure = req.secure;
  const common = { httpOnly: true, secure: isSecure, sameSite: 'Strict', path: '/' };
  res.cookie(COOKIE_SESSION, token, common);
  res.cookie(COOKIE_CSRF, csrf, { ...common, httpOnly: false });
}

export function clearSessionCookies(req, res) {
  const isSecure = req.secure;
  const common = { httpOnly: true, secure: isSecure, sameSite: 'Strict', path: '/' };
  res.clearCookie(COOKIE_SESSION, common);
  res.clearCookie(COOKIE_CSRF, { ...common, httpOnly: false });
}

// ── Auth middleware ───────────────────────────────────────────────────────────

export async function authMiddleware(req, _res, next) {
  const token = req.cookies?.[COOKIE_SESSION];
  if (!token) { req.user = null; return next(); }
  const payload = await verifyJwt(token);
  if (!payload) { req.user = null; return next(); }
  const users = loadUsers();
  const u = users.find(x => x.id === payload.sub);
  if (!u) { req.user = null; return next(); }

  // Ensure jti is still active (not revoked by logout or password change).
  const activeSessions = loadSessions(u.id);
  const isActive = activeSessions.some(s => s.jti === payload.jti);
  if (!isActive) {
    req.user = null;
    return next();
  }

  req.user = { id: u.id, emailHash: u.emailHash, jti: payload.jti, exp: payload.exp };
  next();
}

export function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'unauthenticated' });
  next();
}

// ── Session store ─────────────────────────────────────────────────────────────

export function sessionsPath(uid) { return path.join(userVaultDir(uid), 'sessions.enc'); }

// Sessions cache is intentionally disabled (TTL = 0). In PM2 cluster mode,
// a non-zero TTL would mean password-change / logout revocations only take
// effect on the worker that handled the request.
export const _sessionsCache = new Map();
const SESSIONS_CACHE_TTL_MS = 0;

export function loadSessions(uid) {
  const entry = _sessionsCache.get(uid);
  if (entry && Date.now() - entry.ts < SESSIONS_CACHE_TTL_MS) return entry.data;
  const data = readEncryptedFile(sessionsPath(uid), userInfo(uid, 'sessions'), []);
  _sessionsCache.set(uid, { data, ts: Date.now() });
  return data;
}
export function saveSessions(uid, list) {
  writeEncryptedFile(sessionsPath(uid), userInfo(uid, 'sessions'), list);
  _sessionsCache.set(uid, { data: list, ts: Date.now() });
}

// ── Utility helpers ───────────────────────────────────────────────────────────

export function generateUUID() {
  return randomBytes(16).toString('hex');
}

export function constEq(a, b) {
  const ab = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function getClientIp(req) {
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

export function parseUA(ua) {
  const os =
    /Macintosh|Mac OS X/i.test(ua) ? 'macOS' :
    /Windows NT 10/i.test(ua)      ? 'Windows 10/11' :
    /Windows/i.test(ua)            ? 'Windows' :
    /iPhone|iPad/i.test(ua)        ? 'iOS' :
    /Android/i.test(ua)            ? 'Android' :
    /Linux/i.test(ua)              ? 'Linux' : 'Unknown OS';

  const br =
    /Vivaldi/i.test(ua)                              ? 'Vivaldi' :
    /Edg\//i.test(ua)                                ? 'Edge' :
    /OPR\//i.test(ua) || /Opera/i.test(ua)           ? 'Opera' :
    /Chrome\/\d/i.test(ua) && !/Chromium/i.test(ua)  ? 'Chrome' :
    /Firefox\/\d/i.test(ua)                          ? 'Firefox' :
    /Safari\/\d/i.test(ua)                           ? 'Safari' : 'Unknown Browser';
  return `${os} - ${br}`;
}

export async function recordSession(uid, jti, req) {
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

    // Lazy import to break circular dep: session.js ← audit.js ← session.js
    const { getServerPublicIp } = await import('./audit.js');
    const isLoopback = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
    let displayIp;
    if (isLoopback) {
      displayIp = (await getServerPublicIp()) || 'Local';
    } else {
      const dailySalt = new Date().toISOString().slice(0, 10);
      displayIp = createHash('sha256').update(ip + dailySalt).digest('hex').substring(0, 8);
    }

    updated.push({
      jti,
      id: jti,
      timestamp: Date.now(),
      deviceName,
      ip:        displayIp,
      isCurrent: true,
    });
    const trimmed = updated.length > 20 ? updated.slice(updated.length - 20) : updated;
    saveSessions(uid, trimmed);
  } finally {
    if (release) await release().catch(() => {});
  }
}
