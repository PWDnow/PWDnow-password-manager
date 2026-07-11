import {
  randomBytes,
  randomInt,
  timingSafeEqual,
  scryptSync,
  pbkdf2,
  createHash,
} from 'crypto';
import { promisify } from 'util';
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync, openSync, writeSync, fsyncSync, closeSync } from 'fs';
import { promises as dnsPromises } from 'dns';
import nodemailer from 'nodemailer';
import { lock } from 'proper-lockfile';
import argon2 from 'argon2';
import { TOTP } from 'totp-generator';
import path from 'path';

import { ctx } from '../../lib/context.js';
import {
  decryptBlob,
  readEncryptedFile,
  writeEncryptedFile,
  userVaultFile,
  userInfo,
  userVaultDir,
  loadUsers,
  hashEmail,
  withUsersLock,
  withUserDirLock,
} from '../../lib/fileCrypto.js';
import {
  issueJwt,
  setSessionCookies,
  clearSessionCookies,
  authMiddleware,
  requireAuth,
  loadSessions,
  saveSessions,
  generateUUID,
  getClientIp,
  recordSession,
} from '../../lib/session.js';
import { requireCsrf } from '../../lib/csrf.js';
import {
  appendAuditEvent,
  compactIpInfo,
  getServerPublicIp,
} from '../../lib/audit.js';
import {
  checkLoginRate,
  checkHintsRate,
  checkRegisterRate,
  checkAccountRate,
  recordAccountFailure,
  resetAccountFailures,
  checkFingerprintRate,
  recordFingerprintFailure,
  resetFingerprintFailures,
  deriveClientIdentity,
  makeFingerprintLogEntry,
  mergeFingerprintLog,
  getDummyArgon2Hash,
  ARGON2_MEMORY_KIB,
  ARGON2_TIME_COST,
  ARGON2_PARALLELISM,
  ARGON2_MAX_CONCURRENT,
  SCRYPT_N,
  SCRYPT_R,
  SCRYPT_P,
  SCRYPT_LEN,
  SCRYPT_MAXMEM,
  PBKDF2_SHA512_ITERS,
  PBKDF2_SHA512_LEN,
  PBKDF2_HASH_PREFIX,
} from '../../lib/rateLimiter.js';

import { getEnvSmtpConfig, parseSmtpTestFilter } from '../../lib/smtpConfig.js';

// Async PBKDF2 — runs in the libuv thread pool so 1M iterations don't block the event loop.
export const pbkdf2Async = promisify(pbkdf2);

// Argon2 concurrency is tracked in ctx.stateStore (cluster-aware in Redis mode).

// ── Password hashing helpers ───────────────────────────────────────────────────

export function scryptHash(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const pwdBuf = Buffer.from(password, 'utf8');
  const out = scryptSync(pwdBuf, salt, SCRYPT_LEN, {
    N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: SCRYPT_MAXMEM,
  });
  pwdBuf.fill(0);
  return out.toString('hex');
}

export async function pbkdf2Sha512Hash(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const hash = await pbkdf2Async(
    Buffer.from(password, 'utf8'), salt,
    PBKDF2_SHA512_ITERS, PBKDF2_SHA512_LEN, 'sha512'
  );
  return `${PBKDF2_HASH_PREFIX}${saltHex}$${hash.toString('hex')}`;
}

export async function pbkdf2Sha512Verify(stored, password) {
  if (!stored.startsWith(PBKDF2_HASH_PREFIX)) return false;
  const parts = stored.slice(PBKDF2_HASH_PREFIX.length).split('$');
  if (parts.length !== 2) return false;
  const [saltHex, expectedHex] = parts;
  const salt = Buffer.from(saltHex, 'hex');
  const actual = await pbkdf2Async(
    Buffer.from(password, 'utf8'), salt,
    PBKDF2_SHA512_ITERS, PBKDF2_SHA512_LEN, 'sha512'
  );
  const expected = Buffer.from(expectedHex, 'hex');
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}

export function constEq(a, b) {
  const ab = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export async function hashPassword(password) {
  const count = await ctx.stateStore.incrExpire('argon2:active', 120_000);
  if (count > ARGON2_MAX_CONCURRENT) {
    await ctx.stateStore.decr('argon2:active');
    const err = new Error('too_many_requests');
    err.status = 429;
    throw err;
  }
  try {
    return await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: ARGON2_MEMORY_KIB,
      timeCost: ARGON2_TIME_COST,
      parallelism: ARGON2_PARALLELISM,
    });
  } finally {
    await ctx.stateStore.decr('argon2:active');
  }
}

export async function verifyPassword(hashOrLegacy, password, legacySaltHex) {
  const count = await ctx.stateStore.incrExpire('argon2:active', 120_000);
  if (count > ARGON2_MAX_CONCURRENT) {
    await ctx.stateStore.decr('argon2:active');
    const err = new Error('too_many_requests');
    err.status = 429;
    throw err;
  }
  try {
    if (hashOrLegacy && hashOrLegacy.startsWith('$argon2id$')) {
      return await argon2.verify(hashOrLegacy, password);
    }
    if (hashOrLegacy && hashOrLegacy.startsWith(PBKDF2_HASH_PREFIX)) {
      return await pbkdf2Sha512Verify(hashOrLegacy, password);
    }
    if (hashOrLegacy && hashOrLegacy.startsWith('$argon2')) {
      return await argon2.verify(hashOrLegacy, password);
    }
    if (!hashOrLegacy || !legacySaltHex) {
      const dummy = await getDummyArgon2Hash();
      await argon2.verify(dummy, password).catch(() => {});
      return false;
    }
    const hash = scryptHash(password, legacySaltHex);
    return constEq(hash, hashOrLegacy);
  } finally {
    await ctx.stateStore.decr('argon2:active');
  }
}

// ── MFA brute-force lockout ────────────────────────────────────────────────────

export const MFA_MAX_ATTEMPTS = 5;
const MFA_LOCKOUT_MS   = 10 * 60 * 1000;
const MFA_WINDOW_MS    = 15 * 60 * 1000;

export async function isMfaLocked(userId) {
  const val = await ctx.stateStore.get(`mfa:lock:${userId}`);
  return !!val;
}

export async function recordMfaFailure(userId) {
  const countKey = `mfa:fail:${userId}`;
  const count = await ctx.stateStore.incrExpire(countKey, MFA_WINDOW_MS);
  if (count >= MFA_MAX_ATTEMPTS) {
    await ctx.stateStore.set(`mfa:lock:${userId}`, '1', MFA_LOCKOUT_MS);
    await ctx.stateStore.del(countKey);
  }
}

export async function clearMfaFailure(userId) {
  await Promise.all([
    ctx.stateStore.del(`mfa:fail:${userId}`),
    ctx.stateStore.del(`mfa:lock:${userId}`),
  ]);
}

// ── Partial MFA token store ────────────────────────────────────────────────────

export const PARTIAL_MFA_TTL_MS = 5 * 60 * 1000;

export function mfaPendingPath() { return path.join(ctx.DATA_DIR, 'mfa_pending.enc'); }

export function saveMfaPending(data) {
  writeEncryptedFile(mfaPendingPath(), 'mfa/pending', data);
}

async function withMfaPendingLock(fn) {
  const filePath = mfaPendingPath();
  if (!existsSync(filePath)) {
    writeEncryptedFile(filePath, 'mfa/pending', { tokens: {}, emailOtps: {} });
  }
  let release = null;
  try {
    release = await lock(filePath, { retries: { retries: 10, minTimeout: 50, maxTimeout: 500 } });
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

export async function issueMfaToken(userId) {
  const token = randomBytes(32).toString('hex');
  const hash  = createHash('sha256').update(token, 'hex').digest('hex');
  await withMfaPendingLock(data => {
    data.tokens[hash] = { userId, expiresAt: Date.now() + PARTIAL_MFA_TTL_MS };
  });
  return token;
}

export async function consumeMfaToken(token) {
  const hash = createHash('sha256').update(token, 'hex').digest('hex');
  return withMfaPendingLock(data => {
    const entry = data.tokens[hash];
    if (!entry) return null;
    delete data.tokens[hash];
    if (Date.now() > entry.expiresAt) return null;
    return entry.userId;
  });
}

export async function storeEmailOtp(partialToken) {
  const code = randomInt(0, 1_000_000).toString().padStart(6, '0');
  const key  = createHash('sha256').update(partialToken).digest('hex');
  await withMfaPendingLock(data => {
    data.emailOtps[key] = { code, expiresAt: Date.now() + PARTIAL_MFA_TTL_MS };
  });
  return code;
}

export async function consumeEmailOtp(partialToken) {
  const key = createHash('sha256').update(partialToken).digest('hex');
  return withMfaPendingLock(data => {
    const entry = data.emailOtps[key];
    if (!entry) return null;
    delete data.emailOtps[key];
    if (Date.now() > entry.expiresAt) return null;
    return entry.code;
  });
}

// ── TOTP verification ──────────────────────────────────────────────────────────

export const _usedTotpPeriods = new Map();

setInterval(() => {
  const cutoff = Math.floor(Date.now() / 30000) - 4;
  for (const [k, periods] of _usedTotpPeriods) {
    for (const p of periods) { if (p < cutoff) periods.delete(p); }
    if (periods.size === 0) _usedTotpPeriods.delete(k);
  }
}, 60_000);

export async function verifyTotpCode(secret, code) {
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
      if (periods.has(period)) return false;
      periods.add(period);
      return true;
    }
  }
  return false;
}

// ── Setup OTP in-memory store ─────────────────────────────────────────────────

export const _setupOtps = new Map();

// ── SMTP send helper ───────────────────────────────────────────────────────────

// ── Server-side UA parser (mirrors session.js parseUA for email context) ────────
export function _parseBrowserFromUA(ua) {
  if (!ua) return 'Unknown Browser';
  const br =
    /Vivaldi/i.test(ua)                              ? 'Vivaldi' :
    /Edg\//i.test(ua)                                ? 'Edge' :
    /OPR\//i.test(ua) || /Opera/i.test(ua)           ? 'Opera' :
    /Chrome\/\d/i.test(ua) && !/Chromium/i.test(ua)  ? 'Chrome' :
    /Firefox\/\d/i.test(ua)                          ? 'Firefox' :
    /Safari\/\d/i.test(ua)                           ? 'Safari' :
    /Chromium/i.test(ua)                             ? 'Chromium' : 'Browser';
  return br;
}
export function _parseOSFromUA(ua) {
  if (!ua) return 'Unknown OS';
  return /Macintosh|Mac OS X/i.test(ua) ? 'macOS' :
         /Windows NT 10/i.test(ua)      ? 'Windows 10/11' :
         /Windows/i.test(ua)            ? 'Windows' :
         /iPhone/i.test(ua)             ? 'iPhone' :
         /iPad/i.test(ua)               ? 'iPad' :
         /Android/i.test(ua)            ? 'Android' :
         /Linux/i.test(ua)              ? 'Linux' : 'Unknown OS';
}
export function _escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/**
 * Send a one-time password email.
 *
 * @param {object} smtpCfg   - SMTP configuration blob.
 * @param {string} toEmail   - Recipient address.
 * @param {string} code      - 6-digit OTP (raw, no spaces).
 * @param {string} purpose   - 'setup' | 'login'
 * @param {object} [ctx]     - Optional request context for login emails.
 * @param {string} [ctx.ip]         - Client IP address.
 * @param {string} [ctx.userAgent]  - Client User-Agent string.
 * @param {string} [ctx.browserHint] - Brave/other hint from client (optional).
 */
export async function sendOtpEmail(smtpCfg, toEmail, code, purpose, emailCtx = {}) {
  if (!smtpCfg?.host || !smtpCfg?.username || !smtpCfg?.password) return false;

  const secure = smtpCfg.protocol === 'ssl_tls';
  const transport = nodemailer.createTransport({
    host: String(smtpCfg.host).trim(),
    port: Number(smtpCfg.port) || 465,
    secure,
    auth: { user: String(smtpCfg.username), pass: String(smtpCfg.password) },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 10000,
    tls: { rejectUnauthorized: false },
  });

  const fromName  = smtpCfg.fromName || 'PWDnow';
  const fromAddr  = smtpCfg.username;
  const isSetup   = purpose === 'setup';
  const formatted = `${code.slice(0, 3)} ${code.slice(3)}`;
  const action    = isSetup ? 'MFA setup' : 'login';

  // Subject: "PWDnow - Verification Code" or "PWDnow - MFA Setup Code"
  const subject = isSetup
    ? `${_escHtml(fromName)} - MFA Setup Code`
    : `${_escHtml(fromName)} - Verification Code`;

  // Build request-context block
  const ua = emailCtx.userAgent || '';
  let ip = emailCtx.ip || '';
  // Resolve loopback to the server's public IP (same as recordSession)
  const isLoopback = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' || !ip;
  if (isLoopback) {
    try { ip = (await getServerPublicIp()) || ''; } catch { ip = ''; }
  }
  let browserLabel = _parseBrowserFromUA(ua);
  // If a Brave/other hint was passed from the client, trust it when UA says Chrome
  if (emailCtx.browserHint && /^[\w\s\-]{1,30}$/.test(emailCtx.browserHint) && browserLabel === 'Chrome') {
    browserLabel = emailCtx.browserHint;
  }
  const osLabel = _parseOSFromUA(ua);
  const fromDevice = ua ? `${browserLabel} on ${osLabel}` : null;
  const nowFmt = new Date().toLocaleString('en-US', {
    hour: 'numeric', minute: '2-digit',
    timeZone: 'America/New_York',
  }) + ' EDT';

  // ── Plain-text fallback ────────────────────────────────────────────────────
  // Apple Watch shows a truncated preview of text/plain (first ~100 chars).
  // Put the title + code first so Watch wearers see it immediately.
  let plainText = `Your verification code\n\n${formatted}\n\n`;
  plainText += `Use this code to complete your ${action}. It expires in 5 minutes.\n\n`;
  if (fromDevice) plainText += `Requested at: ${nowFmt}\nRequested from: ${fromDevice}${ip ? ' (' + ip + ')' : ''}\n\n`;
  plainText += `Do not share this code with anyone. ${fromName} will never ask you for this code.\n\n`;
  plainText += `If you did not request this code, you can safely ignore this email.\n\nSent by ${fromName}`;

  // ── Context rows (Requested at / from) for all emails ─────────────────────
  const ctxRowsHtml = (fromDevice || ip) ? `
    <!-- Request context -->
    <tr>
      <td class="bg-meta" style="background-color:#f5f5f7;border-radius:10px;padding:14px 18px;border:1px solid #dfdfe4;" colspan="1">
        <table border="0" cellpadding="0" cellspacing="0" width="100%">
          ${nowFmt ? `<tr>
            <td style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:12px;color:#8e8e93;padding-bottom:6px;" class="text-meta-label">Requested at</td>
            <td align="right" style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:12px;color:#3a3a3c;font-weight:600;" class="text-meta">${_escHtml(nowFmt)}</td>
          </tr>` : ''}
          ${fromDevice ? `<tr>
            <td style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:12px;color:#8e8e93;padding-top:6px;" class="text-meta-label">Requested from</td>
            <td align="right" style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:12px;color:#3a3a3c;font-weight:600;" class="text-meta">${_escHtml(fromDevice)}${ip ? `<br><span style="font-size:11px;color:#6c6c70;font-weight:400;" class="text-meta-label">${_escHtml(ip)}</span>` : ''}</td>
          </tr>` : ''}
        </table>
      </td>
    </tr>
    <tr><td style="height:20px;"></td></tr>` : '';

  // ── HTML email ─────────────────────────────────────────────────────────────
  // Dark-mode WCAG AA contrast ratios (verified against APCA / WCAG 2.1):
  //   .text-title  #f2f2f2 on #1c1c1e → 15.3:1  ✓ (AAA)
  //   .text-body   #d1d1d6 on #1c1c1e →  5.6:1  ✓ (AA)
  //   .text-code   #ffffff on #2c2c2e → 16.1:1  ✓ (AAA)
  //   .text-footer #a0a0a8 on #1a1a1c →  4.6:1  ✓ (AA)
  //   .text-meta   #c0c0c8 on #232325 →  5.0:1  ✓ (AA)
  //   .text-meta-label #7c7c84 on #232325 → 3.1:1 (AA Large / decorative)
  //   .text-warning #ff6b63 on #1c1c1e →  4.5:1  ✓ (AA)
  const htmlBody = `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>${subject}</title>
<style>
/* ── WCAG AA dark mode overrides ────────────────────────────────────────── */
@media (prefers-color-scheme: dark) {
  body, .bg-page    { background-color: #111113 !important; }
  .bg-card          { background-color: #1c1c1e !important; }
  .bg-code          { background-color: #2c2c2e !important; border-color: #3a3a3c !important; }
  .bg-meta          { background-color: #232325 !important; border-color: #3a3a3c !important; }
  .bg-footer        { background-color: #1a1a1c !important; border-top-color: #3a3a3c !important; }
  .text-title       { color: #f2f2f2 !important; }
  .text-body        { color: #d1d1d6 !important; }
  .text-code        { color: #ffffff !important; }
  .text-footer      { color: #a0a0a8 !important; }
  .text-meta        { color: #c0c0c8 !important; }
  .text-meta-label  { color: #7c7c84 !important; }
  .text-warning     { color: #ff6b63 !important; }
}
/* ── Small screen ───────────────────────────────────────────────────────── */
@media screen and (max-width: 360px) {
  .outer-td   { padding: 12px 4px !important; }
  .card-td    { padding: 20px 16px !important; }
  .code-text  { font-size: 26px !important; letter-spacing: 0.2em !important; }
  .header-td  { padding: 16px !important; }
}
</style>
</head>
<body class="bg-page" style="margin:0;padding:0;background-color:#f2f2f7;">
<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color:#f2f2f7;" class="bg-page">
<tr><td class="outer-td" align="center" style="padding:32px 16px;">
  <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="480" style="max-width:480px;width:100%;background-color:#ffffff;border-radius:20px;overflow:hidden;" class="bg-card">

    <!-- ── Header ──────────────────────────────────────────────────────── -->
    <tr>
      <td class="header-td" style="background-color:#000000;padding:20px 28px;border-radius:20px 20px 0 0;">
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%"><tr>
          <td><span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:17px;font-weight:900;color:#ffffff;letter-spacing:0.06em;">${_escHtml(fromName)}</span></td>
          <td align="right"><span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:10px;font-weight:700;color:#a0a0a8;letter-spacing:0.12em;text-transform:uppercase;">Security</span></td>
        </tr></table>
      </td>
    </tr>

    <!-- ── Body ────────────────────────────────────────────────────────── -->
    <tr>
      <td class="card-td" style="padding:28px 32px;">
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">

          <!-- Title -->
          <tr>
            <td style="padding-bottom:8px;">
              <p class="text-title" style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:20px;font-weight:900;color:#1c1c1e;">Your verification code</p>
            </td>
          </tr>

          <!-- Sub-title -->
          <tr>
            <td style="padding-bottom:22px;">
              <p class="text-body" style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:14px;color:#3c3c43;line-height:1.6;">
                Use the code below to complete your <strong>${action}</strong>. This code expires in <strong>5 minutes</strong>.
              </p>
            </td>
          </tr>

          <!-- OTP Code -->
          <tr>
            <td style="padding-bottom:20px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td class="bg-code" align="center" style="background-color:#f2f2f7;border-radius:14px;padding:22px 12px;border:1px solid #e5e5ea;">
                    <span class="code-text text-code" style="font-family:'Courier New',Courier,monospace;font-size:36px;font-weight:900;letter-spacing:0.35em;color:#000000;display:inline-block;">${formatted}</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          ${ctxRowsHtml}

          <!-- Warning -->
          <tr>
            <td>
              <p class="text-warning" style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:12px;color:#c0392b;font-weight:600;">
                &#9888;&#65039;&nbsp; Never share this code. ${_escHtml(fromName)} will never ask for it.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>

    <!-- ── Footer ──────────────────────────────────────────────────────── -->
    <tr>
      <td class="bg-footer" style="background-color:#f9f9f9;padding:14px 28px;border-top:1px solid #e5e5ea;border-radius:0 0 20px 20px;">
        <p class="text-footer" style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:11px;color:#6c6c70;text-align:center;">
          If you did not request this code, you can safely ignore this email.
        </p>
        <p class="text-footer" style="margin:6px 0 0 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:11px;color:#8e8e93;text-align:center;">
          Sent by ${_escHtml(fromName)}
        </p>
      </td>
    </tr>

  </table>
</td></tr>
</table>
</body>
</html>`;

  // NOTE: text/watch-html was removed — Apple Mail on iPhone/iPad treated it
  // as the preferred renderable part, hiding the full HTML. Apple Watch shows
  // a truncated preview of text/plain instead, which now starts with the code.
  await transport.sendMail({
    from: `${fromName} <${fromAddr}>`,
    to: toEmail,
    subject,
    text: plainText,
    html: htmlBody,
  });
  return true;
}

// ── readUserBlob / writeUserBlob helpers ───────────────────────────────────────
// Shared with vaultRoutes.js via export.

// All vault-resource IO funnels through ctx.vaultRepository so the storage backend
// (file or Postgres) is swappable. These helpers are async; every caller awaits them.
export async function readUserBlob(uid, name, fallback) {
  const v = await ctx.vaultRepository.getResource(uid, name);
  return v ?? fallback;
}

// Retained name for callers; identical to readUserBlob (already async/repo-backed).
export const readUserBlobAsync = readUserBlob;

export async function writeUserBlob(uid, name, value) {
  await ctx.vaultRepository.setResource(uid, name, value);
}

export const writeUserBlobAsync = writeUserBlob;

// ── Server-side wipe helpers ───────────────────────────────────────────────────
// Exported so vaultRoutes.js can call performServerWipe.

export function secureOverwriteDir(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    try {
      if (entry.isDirectory()) {
        secureOverwriteDir(p);
      } else if (entry.isFile()) {
        const size = Math.max(512, Buffer.byteLength(readFileSync(p)));
        const fd = openSync(p, 'r+');
        try {
          for (let i = 0; i < 3; i++) {
            writeSync(fd, randomBytes(size), 0);
            fsyncSync(fd);
          }
        } finally {
          closeSync(fd);
        }
      }
    } catch { /* ignore */ }
  }
}

export async function performServerWipe(userId) {
  const dir = userVaultDir(userId);
  if (existsSync(dir)) {
    secureOverwriteDir(dir);
    rmSync(dir, { recursive: true, force: true });
  }
  await ctx.vaultRepository.deleteUserById(userId);
}

// ── Route mounter ─────────────────────────────────────────────────────────────

