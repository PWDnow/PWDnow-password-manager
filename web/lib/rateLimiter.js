import { randomBytes, createHash } from 'crypto';
import argon2 from 'argon2';
import { getClientIp } from './session.js';

// ── Argon2id parameters per NIST SP 800-63B-4 §5.1.1.2 (AAL3) ────────────────

export const ARGON2_MEMORY_KIB  = 128 * 1024; // 128 MiB
export const ARGON2_TIME_COST   = 3;
export const ARGON2_PARALLELISM = 1;

// Concurrency gate — at 128 MiB per hash, unconstrained parallelism exhausts RAM.
export let _argon2ActiveCount = 0;
export const ARGON2_MAX_CONCURRENT = 3;

// Scrypt constants (legacy verification only)
export const SCRYPT_N      = 1 << 17;
export const SCRYPT_R      = 8;
export const SCRYPT_P      = 1;
export const SCRYPT_LEN    = 64;
export const SCRYPT_MAXMEM = 256 * 1024 * 1024;

// PBKDF2-HMAC-SHA-512, 1,000,000 iterations (CNSA 2.0 requirement — legacy verification only).
export const PBKDF2_SHA512_ITERS = 1_000_000;
export const PBKDF2_SHA512_LEN   = 64;
export const PBKDF2_HASH_PREFIX  = '$pbkdf2sha512$';

// ── Map cap helper ────────────────────────────────────────────────────────────

// Hard-cap Map sizes to prevent OOM under sustained botnet attack.
export const MAX_RATE_LIMIT_ENTRIES = 100_000;
export function enforceMapCap(map) {
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

// ── Per-IP login rate limiter ─────────────────────────────────────────────────
// Prevents credential-stuffing and Argon2id-DoS. 10 attempts / 5 min per IP.

export const _loginRateLimiter    = new Map();
export const LOGIN_MAX_PER_WINDOW = 10;
export const LOGIN_WINDOW_MS      = 5 * 60 * 1000;

export function checkLoginRate(ip) {
  const now = Date.now();
  let e = _loginRateLimiter.get(ip);
  if (!e || now > e.resetAt) {
    e = { count: 0, resetAt: now + LOGIN_WINDOW_MS };
    _loginRateLimiter.set(ip, e);
    enforceMapCap(_loginRateLimiter);
  }
  const updated = { ...e, count: e.count + 1 };
  _loginRateLimiter.set(ip, updated);
  return updated.count <= LOGIN_MAX_PER_WINDOW;
}

// ── Hints rate limiter ────────────────────────────────────────────────────────
// Email-step hints lookup is read-only; higher tolerance than login limiter.

export const _hintsRateLimiter    = new Map();
export const HINTS_MAX_PER_WINDOW = 60;
export const HINTS_WINDOW_MS      = 5 * 60 * 1000;

export function checkHintsRate(ip) {
  const now = Date.now();
  let e = _hintsRateLimiter.get(ip);
  if (!e || now > e.resetAt) {
    e = { count: 0, resetAt: now + HINTS_WINDOW_MS };
    _hintsRateLimiter.set(ip, e);
    enforceMapCap(_hintsRateLimiter);
  }
  const updated = { ...e, count: e.count + 1 };
  _hintsRateLimiter.set(ip, updated);
  return updated.count <= HINTS_MAX_PER_WINDOW;
}

// ── Per-account lockout ───────────────────────────────────────────────────────
// Blocks distributed attacks (many IPs → one account).

export const _accountLockout = new Map(); // emailHash → { count, lockedUntil }
export const ACCOUNT_LOCKOUT_SCHEDULE_MS = [0, 0, 0, 0, 0, 30000, 60000, 120000, 300000, 600000];

export function checkAccountRate(emailHash) {
  const now = Date.now();
  const e = _accountLockout.get(emailHash) ?? { count: 0, lockedUntil: 0 };
  if (e.lockedUntil && now < e.lockedUntil) return false; // still locked
  if (e.lockedUntil && now >= e.lockedUntil) {
    e.count = 0; e.lockedUntil = 0; // lockout expired, reset
  }
  return true; // allow — caller increments on failure
}

export function recordAccountFailure(emailHash) {
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

export function resetAccountFailures(emailHash) {
  _accountLockout.delete(emailHash);
}

// ── Per-fingerprint lockout ────────────────────────────────────────────────────
// C-1′ defence — throttles even when account-lockout gate is bypassed (duress).

export const _fingerprintLockout = new Map();
export const FINGERPRINT_LOCKOUT_SCHEDULE_MS = [0, 0, 0, 0, 0, 30000, 60000, 120000, 300000, 600000];

export function deriveClientIdentity(req, fp) {
  const ip = getClientIp(req);
  const ua = req.headers['user-agent'] || '';
  const screen   = fp && typeof fp.screen   === 'string' ? fp.screen.slice(0, 32) : '';
  const visitor  = fp && typeof fp.visitorId === 'string' ? fp.visitorId.slice(0, 64) : '';
  return createHash('sha256').update(`${ip}|${ua}|${screen}|${visitor}`, 'utf8').digest('hex');
}

export function checkFingerprintRate(clientIdentity) {
  const now = Date.now();
  const e = _fingerprintLockout.get(clientIdentity) ?? { count: 0, lockedUntil: 0 };
  if (e.lockedUntil && now < e.lockedUntil) return false;
  if (e.lockedUntil && now >= e.lockedUntil) {
    e.count = 0; e.lockedUntil = 0;
  }
  return true;
}

export function recordFingerprintFailure(clientIdentity) {
  const e = _fingerprintLockout.get(clientIdentity) ?? { count: 0, lockedUntil: 0 };
  const count = e.count + 1;
  const lockMs = FINGERPRINT_LOCKOUT_SCHEDULE_MS[Math.min(count, FINGERPRINT_LOCKOUT_SCHEDULE_MS.length - 1)];
  _fingerprintLockout.set(clientIdentity, {
    count,
    lockedUntil: lockMs > 0 ? Date.now() + lockMs : 0,
  });
  enforceMapCap(_fingerprintLockout);
}

export function resetFingerprintFailures(clientIdentity) {
  _fingerprintLockout.delete(clientIdentity);
}

// ── Fingerprint log ring buffer ────────────────────────────────────────────────
// Per user, cap 32 distinct fingerprints. Exposed in Settings → Recent Devices.

export const FINGERPRINT_LOG_CAP = 32;

export function makeFingerprintLogEntry(clientIdentity, fp, req, success) {
  const now = Date.now();
  return {
    id: clientIdentity,
    visitorId: fp && typeof fp.visitorId === 'string' ? fp.visitorId.slice(0, 64) : '',
    screen:    fp && typeof fp.screen    === 'string' ? fp.screen.slice(0, 32)   : '',
    timezone:  fp && typeof fp.timezone  === 'string' ? fp.timezone.slice(0, 64) : '',
    locale:    fp && typeof fp.locale    === 'string' ? fp.locale.slice(0, 16)   : '',
    ip:        getClientIp(req),
    ua:        (req.headers['user-agent'] || '').slice(0, 256),
    firstSeen: now,
    lastSeen:  now,
    failureCount: success ? 0 : 1,
    successCount: success ? 1 : 0,
  };
}

export function mergeFingerprintLog(log, newEntry) {
  const list = Array.isArray(log) ? log.slice() : [];
  const existingIdx = list.findIndex(e => e && e.id === newEntry.id);
  if (existingIdx !== -1) {
    const ex = list[existingIdx];
    list[existingIdx] = {
      ...ex,
      ip: newEntry.ip,
      ua: newEntry.ua,
      lastSeen: newEntry.lastSeen,
      failureCount: (Number(ex.failureCount) || 0) + (Number(newEntry.failureCount) || 0),
      successCount: (Number(ex.successCount) || 0) + (Number(newEntry.successCount) || 0),
    };
    return list;
  }
  list.push(newEntry);
  if (list.length > FINGERPRINT_LOG_CAP) list.splice(0, list.length - FINGERPRINT_LOG_CAP);
  return list;
}

// ── Per-IP registration rate limiter ─────────────────────────────────────────

export const _registerRateLimiter    = new Map();
export const REGISTER_MAX_PER_WINDOW = 5;
export const REGISTER_WINDOW_MS      = 60 * 60 * 1000;

export function checkRegisterRate(ip) {
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

// ── Per-IP emergency rate limiter ─────────────────────────────────────────────

export const _emergencyRateLimiter    = new Map();
export const EMERGENCY_MAX_PER_WINDOW = 5;
export const EMERGENCY_WINDOW_MS      = 60 * 1000;

export function checkEmergencyRate(ip) {
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

// ── Periodic cleanup of expired entries ──────────────────────────────────────

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of _fingerprintLockout) {
    if (v.lockedUntil && now > v.lockedUntil && v.count === 0) _fingerprintLockout.delete(k);
  }
  for (const map of [_loginRateLimiter, _registerRateLimiter, _emergencyRateLimiter, _hintsRateLimiter]) {
    for (const [k, v] of map) { if (now > v.resetAt) map.delete(k); }
  }
}, 5 * 60 * 1000);

// ── Dummy Argon2id hash for timing equalisation ────────────────────────────────
// Used to equalise timing on the rate-limit-blocked path. Computed at module
// load with a random throw-away password so the hash is real (libargon2 won't
// short-circuit) and verifying against it costs the same ~6-8 s a real
// verification does. Critical: never use this hash as proof-of-knowledge.

let _dummyArgon2Hash = null;
export async function getDummyArgon2Hash() {
  if (_dummyArgon2Hash) return _dummyArgon2Hash;
  try {
    _dummyArgon2Hash = await argon2.hash(randomBytes(32).toString('hex'), {
      type: argon2.argon2id,
      memoryCost: ARGON2_MEMORY_KIB,
      timeCost: ARGON2_TIME_COST,
      parallelism: ARGON2_PARALLELISM,
    });
  } catch {
    _dummyArgon2Hash = '$argon2id$v=19$m=131072,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  }
  return _dummyArgon2Hash;
}
// Pre-warm at module load so the first blocked request doesn't pay the hashing cost.
getDummyArgon2Hash().catch(() => {});
