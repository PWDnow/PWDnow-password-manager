import { randomBytes, createHash } from 'crypto';
import argon2 from 'argon2';
import { getClientIp } from './session.js';
import { ctx } from './context.js';

// ── Argon2id parameters per NIST SP 800-63B-4 §5.1.1.2 (AAL3) ────────────────

export const ARGON2_MEMORY_KIB  = 128 * 1024; // 128 MiB
export const ARGON2_TIME_COST   = 3;
export const ARGON2_PARALLELISM = 1;

// Concurrency gate constant — enforced via StateStore (cluster-wide in Redis mode).
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

// ── Per-IP login rate limiter ─────────────────────────────────────────────────
// 10 attempts / 5 min per IP. Stored in StateStore — cluster-aware in Redis mode.

export const LOGIN_MAX_PER_WINDOW = 10;
export const LOGIN_WINDOW_MS      = 5 * 60 * 1000;

export async function checkLoginRate(ip, res = null) {
  const count = await ctx.stateStore.incrExpire(`rl:login:${ip}`, LOGIN_WINDOW_MS);
  if (res) {
    res.setHeader('X-RateLimit-Limit', LOGIN_MAX_PER_WINDOW);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, LOGIN_MAX_PER_WINDOW - count));
    if (count > LOGIN_MAX_PER_WINDOW) res.setHeader('Retry-After', Math.ceil(LOGIN_WINDOW_MS / 1000));
  }
  return count <= LOGIN_MAX_PER_WINDOW;
}

// ── Hints rate limiter ────────────────────────────────────────────────────────

export const HINTS_MAX_PER_WINDOW = 60;
export const HINTS_WINDOW_MS      = 5 * 60 * 1000;

export async function checkHintsRate(ip, res = null) {
  const count = await ctx.stateStore.incrExpire(`rl:hints:${ip}`, HINTS_WINDOW_MS);
  if (res) {
    res.setHeader('X-RateLimit-Limit', HINTS_MAX_PER_WINDOW);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, HINTS_MAX_PER_WINDOW - count));
    if (count > HINTS_MAX_PER_WINDOW) res.setHeader('Retry-After', Math.ceil(HINTS_WINDOW_MS / 1000));
  }
  return count <= HINTS_MAX_PER_WINDOW;
}

// ── Per-account lockout ───────────────────────────────────────────────────────
// Blocks distributed attacks (many IPs → one account).

export const ACCOUNT_LOCKOUT_SCHEDULE_MS = [0, 0, 0, 0, 0, 30000, 60000, 120000, 300000, 600000];

export async function checkAccountRate(emailHash) {
  const raw = await ctx.stateStore.get(`lockout:acct:${emailHash}`);
  if (!raw) return true;
  const e = JSON.parse(raw);
  if (e.lockedUntil && Date.now() < e.lockedUntil) return false;
  return true;
}

export async function recordAccountFailure(emailHash) {
  const raw = await ctx.stateStore.get(`lockout:acct:${emailHash}`);
  const prev = raw ? JSON.parse(raw) : { count: 0, lockedUntil: 0 };
  const count = prev.count + 1;
  const lockMs = ACCOUNT_LOCKOUT_SCHEDULE_MS[Math.min(count, ACCOUNT_LOCKOUT_SCHEDULE_MS.length - 1)];
  const lockedUntil = lockMs > 0 ? Date.now() + lockMs : 0;
  const ttlMs = Math.max(lockMs || 0, 60 * 60 * 1000); // retain for at least 1h
  await ctx.stateStore.set(`lockout:acct:${emailHash}`, JSON.stringify({ count, lockedUntil }), ttlMs);
}

export async function resetAccountFailures(emailHash) {
  await ctx.stateStore.del(`lockout:acct:${emailHash}`);
}

// ── Per-fingerprint lockout ────────────────────────────────────────────────────
// C-1′ defence — throttles even when account-lockout gate is bypassed (duress).

export const FINGERPRINT_LOCKOUT_SCHEDULE_MS = [0, 0, 0, 0, 0, 30000, 60000, 120000, 300000, 600000];

export async function checkFingerprintRate(clientIdentity) {
  const raw = await ctx.stateStore.get(`lockout:fp:${clientIdentity}`);
  if (!raw) return true;
  const e = JSON.parse(raw);
  if (e.lockedUntil && Date.now() < e.lockedUntil) return false;
  return true;
}

export async function recordFingerprintFailure(clientIdentity) {
  const raw = await ctx.stateStore.get(`lockout:fp:${clientIdentity}`);
  const prev = raw ? JSON.parse(raw) : { count: 0, lockedUntil: 0 };
  const count = prev.count + 1;
  const lockMs = FINGERPRINT_LOCKOUT_SCHEDULE_MS[Math.min(count, FINGERPRINT_LOCKOUT_SCHEDULE_MS.length - 1)];
  const lockedUntil = lockMs > 0 ? Date.now() + lockMs : 0;
  const ttlMs = Math.max(lockMs || 0, 60 * 60 * 1000);
  await ctx.stateStore.set(`lockout:fp:${clientIdentity}`, JSON.stringify({ count, lockedUntil }), ttlMs);
}

export async function resetFingerprintFailures(clientIdentity) {
  await ctx.stateStore.del(`lockout:fp:${clientIdentity}`);
}

// ── Fingerprint log ring buffer ────────────────────────────────────────────────
// Per user, cap 32 distinct fingerprints. Exposed in Settings → Recent Devices.

export const FINGERPRINT_LOG_CAP = 32;

export function deriveClientIdentity(req, fp) {
  const ip = getClientIp(req);
  const ua = req.headers['user-agent'] || '';
  const screen   = fp && typeof fp.screen   === 'string' ? fp.screen.slice(0, 32) : '';
  const visitor  = fp && typeof fp.visitorId === 'string' ? fp.visitorId.slice(0, 64) : '';
  return createHash('sha256').update(`${ip}|${ua}|${screen}|${visitor}`, 'utf8').digest('hex');
}

// WEB-06: a *separate*, narrower identity used only for the fingerprint
// brute-force lockout bucket. `deriveClientIdentity` above intentionally
// includes client-supplied `screen`/`visitorId` so distinct devices behind
// the same NAT/IP get distinct entries in the Settings "Recent Devices" log
// — but that same client-controlled input means an attacker can rotate
// `visitorId` on every login attempt to mint a fresh lockout bucket each
// time, defeating the fingerprint throttle entirely. The lockout bucket is
// therefore keyed on IP+UA only, neither of which the caller can cheaply
// vary per request the way a body field can be.
export function deriveLockoutIdentity(req) {
  const ip = getClientIp(req);
  const ua = req.headers['user-agent'] || '';
  return createHash('sha256').update(`${ip}|${ua}`, 'utf8').digest('hex');
}

// Recompute the same IP+UA lockout identity from a stored fingerprint-log
// entry (which records the raw ip/ua at the time it was seen) — used so
// DELETE /api/auth/fingerprints/:id can clear the matching lockout bucket
// for the fingerprint being removed.
export function lockoutIdentityFromLogEntry(entry) {
  const ip = entry && typeof entry.ip === 'string' ? entry.ip : '';
  const ua = entry && typeof entry.ua === 'string' ? entry.ua : '';
  return createHash('sha256').update(`${ip}|${ua}`, 'utf8').digest('hex');
}

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

export const REGISTER_MAX_PER_WINDOW = 5;
export const REGISTER_WINDOW_MS      = 60 * 60 * 1000;

// ── /api/rpc daemon-proxy rate limiter (L1) ───────────────────────────────────

export const RPC_MAX_PER_WINDOW = 60;
export const RPC_WINDOW_MS      = 60 * 1000;

export async function checkRpcRate(ip, res = null) {
  const count = await ctx.stateStore.incrExpire(`rl:rpc:${ip}`, RPC_WINDOW_MS);
  if (res) {
    res.setHeader('X-RateLimit-Limit', RPC_MAX_PER_WINDOW);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, RPC_MAX_PER_WINDOW - count));
    if (count > RPC_MAX_PER_WINDOW) res.setHeader('Retry-After', Math.ceil(RPC_WINDOW_MS / 1000));
  }
  return count <= RPC_MAX_PER_WINDOW;
}

export async function checkRegisterRate(ip, res = null) {
  const count = await ctx.stateStore.incrExpire(`rl:register:${ip}`, REGISTER_WINDOW_MS);
  if (res) {
    res.setHeader('X-RateLimit-Limit', REGISTER_MAX_PER_WINDOW);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, REGISTER_MAX_PER_WINDOW - count));
    if (count > REGISTER_MAX_PER_WINDOW) res.setHeader('Retry-After', Math.ceil(REGISTER_WINDOW_MS / 1000));
  }
  return count <= REGISTER_MAX_PER_WINDOW;
}

// Per-email-hash registration limiter (M5): caps how many registration
// attempts a single target email can be probed with, independent of the
// caller's IP, slowing down user-enumeration via repeated /register calls.
export const REGISTER_EMAIL_MAX_PER_WINDOW = 3;
export const REGISTER_EMAIL_WINDOW_MS      = 24 * 60 * 60 * 1000;

export async function checkRegisterEmailRate(emailHash, res = null) {
  const count = await ctx.stateStore.incrExpire(`rl:register:email:${emailHash}`, REGISTER_EMAIL_WINDOW_MS);
  if (res) {
    res.setHeader('X-RateLimit-Limit', REGISTER_EMAIL_MAX_PER_WINDOW);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, REGISTER_EMAIL_MAX_PER_WINDOW - count));
    if (count > REGISTER_EMAIL_MAX_PER_WINDOW) res.setHeader('Retry-After', Math.ceil(REGISTER_EMAIL_WINDOW_MS / 1000));
  }
  return count <= REGISTER_EMAIL_MAX_PER_WINDOW;
}

// ── Per-IP emergency rate limiter ─────────────────────────────────────────────

export const EMERGENCY_MAX_PER_WINDOW = 5;
export const EMERGENCY_WINDOW_MS      = 60 * 1000;

export async function checkEmergencyRate(ip, res = null) {
  const count = await ctx.stateStore.incrExpire(`rl:emergency:${ip}`, EMERGENCY_WINDOW_MS);
  if (res) {
    res.setHeader('X-RateLimit-Limit', EMERGENCY_MAX_PER_WINDOW);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, EMERGENCY_MAX_PER_WINDOW - count));
    if (count > EMERGENCY_MAX_PER_WINDOW) res.setHeader('Retry-After', Math.ceil(EMERGENCY_WINDOW_MS / 1000));
  }
  return count <= EMERGENCY_MAX_PER_WINDOW;
}

// ── Per-IP setup-phase exec rate limiter ──────────────────────────────────────
// /api/ubuntu-pro/attach and /api/ubuntu-pro/enable-fips shell out to `sudo
// pro ...` (up to a 300s timeout). Already gated to localhost + a single-use
// setup token, but a compromised local process could still loop the call and
// pile up subprocesses for the duration of the setup window.

export const SETUP_EXEC_MAX_PER_WINDOW = 5;
export const SETUP_EXEC_WINDOW_MS      = 5 * 60 * 1000;

export async function checkSetupExecRate(ip, res = null) {
  const count = await ctx.stateStore.incrExpire(`rl:setupexec:${ip}`, SETUP_EXEC_WINDOW_MS);
  if (res) {
    res.setHeader('X-RateLimit-Limit', SETUP_EXEC_MAX_PER_WINDOW);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, SETUP_EXEC_MAX_PER_WINDOW - count));
    if (count > SETUP_EXEC_MAX_PER_WINDOW) res.setHeader('Retry-After', Math.ceil(SETUP_EXEC_WINDOW_MS / 1000));
  }
  return count <= SETUP_EXEC_MAX_PER_WINDOW;
}

// ── Per-IP DNS-check rate limiter (WEB-02) ────────────────────────────────────
// /api/system/dns-check and /api/auth/smtp-check each fan out ~35 DNS lookups
// (MX/TXT/DMARC/BIMI + DKIM selector probes) per call. Without a cap here, an
// unauthenticated caller can turn the server into a DNS amplifier/reflector
// against an arbitrary target domain. Capped well below the general nginx
// limit so this specific endpoint is bounded even without the reverse proxy.

export const DNS_CHECK_MAX_PER_WINDOW = 10;
export const DNS_CHECK_WINDOW_MS      = 60 * 1000;

export async function checkDnsRate(ip, res = null) {
  const count = await ctx.stateStore.incrExpire(`rl:dnscheck:${ip}`, DNS_CHECK_WINDOW_MS);
  if (res) {
    res.setHeader('X-RateLimit-Limit', DNS_CHECK_MAX_PER_WINDOW);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, DNS_CHECK_MAX_PER_WINDOW - count));
    if (count > DNS_CHECK_MAX_PER_WINDOW) res.setHeader('Retry-After', Math.ceil(DNS_CHECK_WINDOW_MS / 1000));
  }
  return count <= DNS_CHECK_MAX_PER_WINDOW;
}

// ── Per-user share-creation rate limiter ──────────────────────────────────────
// Each call writes a new file under the user's shares/ dir with no cap on
// count — without a limiter, a compromised/malicious session could exhaust
// disk space by looping POST /api/vault/shares.

export const SHARE_CREATE_MAX_PER_WINDOW = 20;
export const SHARE_CREATE_WINDOW_MS      = 60 * 60 * 1000;

export async function checkShareCreateRate(uid, res = null) {
  const count = await ctx.stateStore.incrExpire(`rl:sharecreate:${uid}`, SHARE_CREATE_WINDOW_MS);
  if (res) {
    res.setHeader('X-RateLimit-Limit', SHARE_CREATE_MAX_PER_WINDOW);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, SHARE_CREATE_MAX_PER_WINDOW - count));
    if (count > SHARE_CREATE_MAX_PER_WINDOW) res.setHeader('Retry-After', Math.ceil(SHARE_CREATE_WINDOW_MS / 1000));
  }
  return count <= SHARE_CREATE_MAX_PER_WINDOW;
}

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
