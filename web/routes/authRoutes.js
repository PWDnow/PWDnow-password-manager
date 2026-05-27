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

import { ctx } from '../lib/context.js';
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
} from '../lib/fileCrypto.js';
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
} from '../lib/session.js';
import { requireCsrf } from '../lib/csrf.js';
import {
  appendAuditEvent,
  compactIpInfo,
  getServerPublicIp,
} from '../lib/audit.js';
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
} from '../lib/rateLimiter.js';

// Async PBKDF2 — runs in the libuv thread pool so 1M iterations don't block the event loop.
const pbkdf2Async = promisify(pbkdf2);

// ── Concurrency counter ────────────────────────────────────────────────────────
// Local to this module so hashPassword / verifyPassword can mutate it.
let _argon2ActiveCount = 0;

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

function constEq(a, b) {
  const ab = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export async function hashPassword(password) {
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

export async function verifyPassword(hashOrLegacy, password, legacySaltHex) {
  if (_argon2ActiveCount >= ARGON2_MAX_CONCURRENT) {
    const err = new Error('too_many_requests');
    err.status = 429;
    throw err;
  }
  _argon2ActiveCount++;
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
      const DUMMY_HASH = '$argon2id$v=19$m=131072,t=3,p=1$c29tZXNhbHQ$c29tZWhhc2hvdXRwdXQ';
      await argon2.verify(DUMMY_HASH, password).catch(() => {});
      return false;
    }
    const hash = scryptHash(password, legacySaltHex);
    return constEq(hash, hashOrLegacy);
  } finally {
    _argon2ActiveCount--;
  }
}

// ── MFA brute-force lockout ────────────────────────────────────────────────────

const _mfaFailedAttempts = new Map(); // userId → { count, lockedUntil }
const MFA_MAX_ATTEMPTS  = 5;
const MFA_LOCKOUT_MS    = 10 * 60 * 1000;

export function isMfaLocked(userId) {
  const e = _mfaFailedAttempts.get(userId);
  if (!e?.lockedUntil) return false;
  if (Date.now() >= e.lockedUntil) { _mfaFailedAttempts.delete(userId); return false; }
  return true;
}

export function recordMfaFailure(userId) {
  const e = _mfaFailedAttempts.get(userId) ?? { count: 0, lockedUntil: 0 };
  e.count++;
  if (e.count >= MFA_MAX_ATTEMPTS) {
    e.lockedUntil = Date.now() + MFA_LOCKOUT_MS;
    e.count = 0;
  }
  _mfaFailedAttempts.set(userId, e);
}

export function clearMfaFailure(userId) {
  _mfaFailedAttempts.delete(userId);
}

// ── Partial MFA token store ────────────────────────────────────────────────────

const PARTIAL_MFA_TTL_MS = 5 * 60 * 1000;

function mfaPendingPath() { return path.join(ctx.DATA_DIR, 'mfa_pending.enc'); }

function saveMfaPending(data) {
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

const _usedTotpPeriods = new Map();

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

const _setupOtps = new Map();

// ── SMTP send helper ───────────────────────────────────────────────────────────

// ── Server-side UA parser (mirrors session.js parseUA for email context) ────────
function _parseBrowserFromUA(ua) {
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
function _parseOSFromUA(ua) {
  if (!ua) return 'Unknown OS';
  return /Macintosh|Mac OS X/i.test(ua) ? 'macOS' :
         /Windows NT 10/i.test(ua)      ? 'Windows 10/11' :
         /Windows/i.test(ua)            ? 'Windows' :
         /iPhone/i.test(ua)             ? 'iPhone' :
         /iPad/i.test(ua)               ? 'iPad' :
         /Android/i.test(ua)            ? 'Android' :
         /Linux/i.test(ua)              ? 'Linux' : 'Unknown OS';
}
function _escHtml(str) {
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

export function readUserBlob(uid, name, fallback) {
  const filePath = userVaultFile(uid, name);
  const info = userInfo(uid, name);
  if (!existsSync(filePath)) return fallback;
  const raw = readFileSync(filePath);
  const pt = decryptBlob(info, raw);
  return JSON.parse(pt.toString('utf8'));
}

export function readUserBlobAsync(uid, name, fallback) {
  // Thin async wrapper delegating to readEncryptedFile (which is already async-capable).
  return import('../lib/fileCrypto.js').then(({ readEncryptedFileAsync }) =>
    readEncryptedFileAsync(userVaultFile(uid, name), userInfo(uid, name), fallback)
  );
}

export function writeUserBlob(uid, name, value) {
  writeEncryptedFile(userVaultFile(uid, name), userInfo(uid, name), value);
}

export async function writeUserBlobAsync(uid, name, value) {
  const { writeEncryptedFileAsync } = await import('../lib/fileCrypto.js');
  return writeEncryptedFileAsync(userVaultFile(uid, name), userInfo(uid, name), value);
}

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
  await withUsersLock(async (users) => {
    const idx = users.findIndex(x => x.id === userId);
    if (idx !== -1) users.splice(idx, 1);
  });
}

// ── Route mounter ─────────────────────────────────────────────────────────────

export function mountAuthRoutes(app) {

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
    if (loadUsers().some(x => x.emailHash === emailHash)) {
      return res.status(409).json({ error: 'email_taken' });
    }

    let hash;
    try { hash = await hashPassword(password); }
    catch (e) { return res.status(e.status || 500).json({ error: e.message }); }
    const id = randomBytes(16).toString('hex');

    const conflict = await withUsersLock(async (users) => {
      if (users.some(x => x.emailHash === emailHash)) return 'taken';
      users.push({ id, emailHash, passwordHash: hash, salt: null, cryptoSalt: cryptoSalt || null, createdAt: Date.now() });
    });
    if (conflict === 'taken') return res.status(409).json({ error: 'email_taken' });
    mkdirSync(userVaultDir(id), { recursive: true, mode: 0o700 });
    writeEncryptedFile(userVaultFile(id, 'profile'), userInfo(id, 'profile'),
      { firstName, lastName, email: email.trim() });
    writeEncryptedFile(userVaultFile(id, 'credentials'), userInfo(id, 'credentials'), []);
    writeEncryptedFile(userVaultFile(id, 'folders'), userInfo(id, 'folders'), []);
    writeEncryptedFile(userVaultFile(id, 'asset_holder'), userInfo(id, 'asset_holder'),
      { emails: [], phoneNumbers: [], u2fKeys: [] });

    const { token, jti } = await issueJwt(id);
    const csrf = randomBytes(24).toString('hex');
    setSessionCookies(req, res, token, csrf);
    await recordSession(id, jti, req);
    res.json({ ok: true });
  });

  app.post('/api/auth/login-hints', async (req, res) => {
    const { email, hints } = req.body || {};

    if (hints) {
      return authMiddleware(req, res, () => {
        return requireAuth(req, res, () => {
          return requireCsrf(req, res, async () => {
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
            const found = await withUsersLock(async (users) => {
              const userIndex = users.findIndex(x => x.id === req.user.id);
              if (userIndex === -1) return false;
              users[userIndex].loginHints = sanitized;
            });
            if (found === false) return res.status(401).json({ error: 'user_not_found' });
            return res.json({ ok: true });
          });
        });
      });
    }

    if (!checkHintsRate(getClientIp(req))) {
      return res.status(429).json({ error: 'too_many_requests' });
    }

    if (typeof email !== 'string') return res.status(400).json({ error: 'invalid_input' });
    const emailHash = hashEmail(email);
    const users = loadUsers();
    const u = users.find(x => x.emailHash === emailHash);
    const defaults = { totp: false, emailOtp: false, passwordEnabled: true, webauthn: false, passwordlessEnabled: false };
    if (!u || !u.loginHints) {
      return res.json({ hints: defaults });
    }
    const { cryptoSalt: _removed, ...rawHints } = u.loginHints;
    const safeHints = {};
    for (const k of Object.keys(defaults)) {
      if (typeof rawHints[k] === 'boolean') safeHints[k] = rawHints[k];
    }
    return res.json({ hints: { ...defaults, ...safeHints } });
  });

  app.post('/api/auth/crypto-salt', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { cryptoSalt } = req.body || {};
    if (typeof cryptoSalt !== 'string' || !/^[0-9a-f]{32}$/i.test(cryptoSalt)) {
      return res.status(400).json({ error: 'invalid_salt' });
    }
    let finalSalt = null;
    let stored = false;
    const found = await withUsersLock(async (users) => {
      const userIndex = users.findIndex(x => x.id === req.user.id);
      if (userIndex === -1) return false;
      if (!users[userIndex].cryptoSalt) {
        users[userIndex].cryptoSalt = cryptoSalt;
        stored = true;
      }
      finalSalt = users[userIndex].cryptoSalt;
    });
    if (found === false) return res.status(401).json({ error: 'user_not_found' });
    if (stored && process.env.NODE_ENV !== 'production') {
      console.log(`[auth] Stored cryptoSalt for user ${req.user.id}`);
    }
    if (finalSalt) res.setHeader('X-Vault-Salt', finalSalt);
    res.json({ ok: true });
  });

  app.post('/api/auth/login', authMiddleware, async (req, res) => {
    const { email, password, fingerprint } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'invalid_input' });
    }
    const emailHash = hashEmail(email);

    const usersSnapshot = loadUsers();
    const uSnapshot = usersSnapshot.find(x => x.emailHash === emailHash);
    const duressArmed = !!(uSnapshot && uSnapshot.duressEnforce && uSnapshot.duressEnforce.armed);

    const clientIdentity = deriveClientIdentity(req, fingerprint);

    const ipBlocked      = !checkLoginRate(getClientIp(req));
    const fpBlocked      = !checkFingerprintRate(clientIdentity);
    const accountBlocked = !duressArmed && !checkAccountRate(emailHash);
    if (ipBlocked || fpBlocked || accountBlocked) {
      try {
        const dummy = await getDummyArgon2Hash();
        await verifyPassword(dummy, password, null);
      } catch { /* dummy verify failure is fine */ }
      const reason = accountBlocked ? 'account' : (fpBlocked ? 'fingerprint' : 'ip');
      res.setHeader('X-Rate-Limited', reason);
      const errorCode = accountBlocked ? 'account_locked' : 'too_many_requests';
      return res.status(200).json({ ok: false, error: errorCode });
    }

    let authenticated = await verifyPassword(uSnapshot?.passwordHash, password, uSnapshot?.salt);
    let authMethod = 'password';
    let recoveryConsumed = false;

    if (uSnapshot && !authenticated && uSnapshot.recoveryKeyHash) {
      const expired = uSnapshot.recoveryKeyExpiresAt && Date.now() > uSnapshot.recoveryKeyExpiresAt;
      if (!expired && await verifyPassword(uSnapshot.recoveryKeyHash, password, uSnapshot.recoveryKeySalt)) {
        authenticated = true;
        authMethod = 'recovery_key';
        recoveryConsumed = true;
      }
    }

    let newPasswordHash = null;
    if (authenticated && uSnapshot && uSnapshot.passwordHash && !uSnapshot.passwordHash.startsWith('$argon2id$')) {
      try { newPasswordHash = await hashPassword(password); } catch { /* DoS gate hit */ }
    }

    if (!authenticated) {
      if (!duressArmed) recordAccountFailure(emailHash);
      recordFingerprintFailure(clientIdentity);

      if (uSnapshot) {
        await withUsersLock(async (freshUsers) => {
          const fu = freshUsers.find(x => x.id === uSnapshot.id);
          if (!fu) return false;
          const fpEntry = makeFingerprintLogEntry(clientIdentity, fingerprint, req, false);
          fu.fingerprintLog = mergeFingerprintLog(fu.fingerprintLog, fpEntry);
        });
      }

      let duressRemaining = null;
      let duressWipe = false;
      if (uSnapshot && duressArmed) {
        await withUsersLock(async (freshUsers) => {
          const fu = freshUsers.find(x => x.id === uSnapshot.id);
          if (!fu || !fu.duressEnforce || !fu.duressEnforce.armed) return false;
          const max = Math.max(1, Math.min(20, Number(fu.duressEnforce.maxAttempts) || 3));
          const prev = Number(fu.duressFailureCount) || 0;
          const next = prev + 1;
          if (next >= max) {
            duressWipe = true;
            return false;
          }
          duressRemaining = max - next;
          fu.duressFailureCount = next;
        });
        if (duressWipe) {
          appendAuditEvent(uSnapshot.id, { action: 'duress_wipe_triggered', ip: getClientIp(req), success: true });
          try { await performServerWipe(uSnapshot.id); } catch { /* best-effort */ }
        }
      }

      if (uSnapshot && !duressWipe) appendAuditEvent(uSnapshot.id, { action: 'login_failed', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: false, riskFlags: req.ipRecord?.riskFlags ?? [], fingerprintId: clientIdentity.slice(0, 16), screen: fingerprint?.screen, timezone: fingerprint?.timezone });
      const body = { ok: false, error: 'invalid_credentials' };
      if (duressWipe) body.duressWipe = true;
      else if (duressRemaining !== null) body.duressRemaining = duressRemaining;
      return res.status(200).json(body);
    }
    resetAccountFailures(emailHash);
    resetFingerprintFailures(clientIdentity);

    let finalU = null;
    await withUsersLock(async (freshUsers) => {
      const fu = freshUsers.find(x => x.id === uSnapshot.id);
      if (!fu) return false;
      if (recoveryConsumed) {
        fu.recoveryKeyHash = null;
        fu.recoveryKeySalt = null;
        fu.recoveryKeyExpiresAt = null;
      }
      if (newPasswordHash && fu.passwordHash === uSnapshot.passwordHash) {
        fu.passwordHash = newPasswordHash;
        fu.salt = null;
      }
      if ((fu.duressFailureCount || 0) > 0) {
        fu.duressFailureCount = 0;
      }
      const fpEntry = makeFingerprintLogEntry(clientIdentity, fingerprint, req, true);
      fu.fingerprintLog = mergeFingerprintLog(fu.fingerprintLog, fpEntry);
      finalU = { ...fu };
    });
    if (!finalU) {
      return res.status(401).json({ ok: false, error: 'user_not_found' });
    }
    const u = finalU;

    const mfaEnforce = u.mfaEnforce || {};
    const mfaMethods = [];
    if (mfaEnforce.totp  === true) mfaMethods.push('totp');
    if (mfaEnforce.email === true) mfaMethods.push('email');

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
        const profile  = readUserBlob(u.id, 'profile', { email: '' });
        const smtpCfg  = readUserBlob(u.id, 'smtp_config', null);
        const toEmail  = typeof profile.email === 'string' ? profile.email.trim() : '';
        if (toEmail && smtpCfg) {
          const emailCtx = {
            ip: getClientIp(req),
            userAgent: req.headers['user-agent'] || '',
            browserHint: typeof req.body?.fingerprint?.browser === 'string' ? req.body.fingerprint.browser : '',
          };
          sendOtpEmail(smtpCfg, toEmail, otp, 'login', emailCtx).catch(e =>
            console.error('[login-otp-email] send failed:', e.message)
          );
        }
      }
      return res.json({ ok: true, partialToken, methods: mfaMethods });
    }

    const { token, jti } = await issueJwt(u.id);
    const csrf = randomBytes(24).toString('hex');
    setSessionCookies(req, res, token, csrf);
    await recordSession(u.id, jti, req);
    appendAuditEvent(u.id, { action: 'login', auth_method: authMethod, ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [], fingerprintId: clientIdentity.slice(0, 16), screen: fingerprint?.screen, timezone: fingerprint?.timezone });
    if (u.cryptoSalt) res.setHeader('X-Vault-Salt', u.cryptoSalt);
    res.json({ ok: true });
  });

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
      if (typeof emailCode !== 'string') {
        return res.status(401).json({ ok: false, error: 'mfa_required' });
      }
      const stored = await consumeEmailOtp(partialToken);
      if (!stored) {
        recordMfaFailure(u.id);
        appendAuditEvent(u.id, { action: 'mfa_failed', ip: getClientIp(req), success: false });
        return res.status(401).json({ ok: false, error: 'invalid_mfa_code' });
      }
      const supplied = emailCode.trim().slice(0, 8);
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
    if (recoveryKey.length < 26) return res.status(400).json({ error: 'weak_recovery_key' });
    const cleanKey = recoveryKey.replace(/[-\s]/g, '');
    const crockfordRegex = /^[0-9A-HJKMNP-TV-Z]+$/i;
    if (!crockfordRegex.test(cleanKey)) return res.status(400).json({ error: 'invalid_charset' });

    const usersSnap = loadUsers();
    const uSnap = usersSnap.find(x => x.id === req.user.id);
    if (!uSnap) return res.status(401).json({ error: 'user_not_found' });

    const verified = await verifyPassword(uSnap.passwordHash, password, uSnap.salt);
    if (!verified) return res.status(401).json({ error: 'invalid_password' });

    const hash = await hashPassword(recoveryKey);

    const found = await withUsersLock(async (users) => {
      const idx = users.findIndex(x => x.id === req.user.id);
      if (idx === -1) return false;
      if (users[idx].passwordHash !== uSnap.passwordHash) {
        throw Object.assign(new Error('password_changed_concurrently'), { status: 409 });
      }
      users[idx].recoveryKeyHash = hash;
      users[idx].recoveryKeySalt = null;
      users[idx].recoveryKeyGeneratedAt = Date.now();
      users[idx].recoveryKeyExpiresAt = Date.now() + 90 * 24 * 60 * 60 * 1000;
    }).catch(err => {
      if (err && err.status === 409) {
        res.status(409).json({ error: 'password_changed' });
        return 'handled';
      }
      throw err;
    });
    if (found === 'handled') return;
    if (found === false) return res.status(401).json({ error: 'user_not_found' });
    res.json({ ok: true });
  });

  app.get('/api/auth/fingerprints', authMiddleware, requireAuth, (req, res) => {
    const u = loadUsers().find(x => x.id === req.user.id);
    if (!u) return res.status(401).json({ error: 'user_not_found' });
    const list = Array.isArray(u.fingerprintLog) ? u.fingerprintLog : [];
    res.json({ ok: true, fingerprints: list.slice().sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0)) });
  });

  app.delete('/api/auth/fingerprints/:id', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const targetId = String(req.params.id || '');
    if (!/^[0-9a-f]{4,128}$/i.test(targetId)) return res.status(400).json({ error: 'invalid_id' });
    const found = await withUsersLock(async (users) => {
      const idx = users.findIndex(x => x.id === req.user.id);
      if (idx === -1) return false;
      const log = Array.isArray(users[idx].fingerprintLog) ? users[idx].fingerprintLog : [];
      const before = log.length;
      users[idx].fingerprintLog = log.filter(e => e.id !== targetId);
      if (users[idx].fingerprintLog.length === before) return false;
    });
    if (found === false) return res.status(404).json({ error: 'not_found' });
    resetFingerprintFailures(targetId);
    res.json({ ok: true });
  });

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
      if (isMfaLocked(u.id)) return res.status(429).json({ ok: false, error: 'too_many_attempts' });
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

    const usersSnap = loadUsers();
    const uSnap = usersSnap.find(x => x.id === req.user.id);
    if (!uSnap) return res.status(401).json({ error: 'user_not_found' });

    const authenticated = await verifyPassword(uSnap.passwordHash, oldPassword, uSnap.salt);
    if (!authenticated) return res.status(401).json({ error: 'invalid_credentials' });

    const newHash = await hashPassword(newPassword);

    const found = await withUsersLock(async (users) => {
      const idx = users.findIndex(x => x.id === req.user.id);
      if (idx === -1) return false;
      if (users[idx].passwordHash !== uSnap.passwordHash) {
        throw Object.assign(new Error('password_changed_concurrently'), { status: 409 });
      }
      users[idx].salt = null;
      users[idx].passwordHash = newHash;
      users[idx].passwordChangedAt = Date.now();
      users[idx].revocationEpoch = (Number(users[idx].revocationEpoch) || 0) + 1;
    }).catch(err => {
      if (err && err.status === 409) {
        res.status(409).json({ error: 'password_changed' });
        return 'handled';
      }
      throw err;
    });
    if (found === 'handled') return;
    if (found === false) return res.status(401).json({ error: 'user_not_found' });

    await withUserDirLock(req.user.id, async () => {
      saveSessions(req.user.id, []);
    });

    appendAuditEvent(req.user.id, { action: 'password_changed', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true });
  });

  app.get('/api/auth/sessions', authMiddleware, requireAuth, (req, res) => {
    const list = loadSessions(req.user.id)
      .slice()
      .sort((a, b) => b.timestamp - a.timestamp)
      .map(({ jti: _jti, ...rest }) => rest);
    res.json(list);
  });

  app.post('/api/auth/sessions/revoke-others', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    await withUsersLock(async (users) => {
      const idx = users.findIndex(x => x.id === req.user.id);
      if (idx === -1) return false;
      users[idx].revocationEpoch = (Number(users[idx].revocationEpoch) || 0) + 1;
    });
    await withUserDirLock(req.user.id, async () => {
      const list = loadSessions(req.user.id).filter(s => s.jti === req.user.jti);
      saveSessions(req.user.id, list);
    });
    res.json({ ok: true });
  });

  app.post('/api/auth/logout', authMiddleware, requireCsrf, async (req, res) => {
    if (req.user) {
      await withUserDirLock(req.user.id, async () => {
        const list = loadSessions(req.user.id).filter(s => s.jti !== req.user.jti);
        saveSessions(req.user.id, list);
      });
      appendAuditEvent(req.user.id, { action: 'logout', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    }
    clearSessionCookies(req, res);
    res.json({ ok: true });
  });

  const LOOPBACK_RE_SRV = /^(127\.|::1$|::ffff:127\.)/;
  app.get('/api/my-ip', authMiddleware, requireAuth, async (req, res) => {
    const clientIp = getClientIp(req);
    if (!LOOPBACK_RE_SRV.test(clientIp)) return res.json({ ip: clientIp });
    res.json({ ip: (await getServerPublicIp()) ?? '127.0.0.1' });
  });

  // ── SMTP check ─────────────────────────────────────────────────────────────
  app.post('/api/auth/smtp-check', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { host, port, protocol, username, password } = req.body ?? {};
    if (!host || typeof host !== 'string' || !port || !username) {
      return res.status(400).json({ error: 'invalid_input' });
    }

    const smtpHost = host.trim().toLowerCase();
    const BLOCKED_HOST_RE = /^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1|169\.254\.|fd[0-9a-f]{2}:|fc00:)/i;
    if (BLOCKED_HOST_RE.test(smtpHost)) {
      return res.status(400).json({ error: 'invalid_smtp_host' });
    }

    const parts = smtpHost.split('.');
    const domain = parts.length >= 2 ? parts.slice(-2).join('.') : smtpHost;

    const result = {
      domain,
      mx:    { found: false, records: [] },
      spf:   { found: false, record: null },
      dkim:  { found: false, selector: null, record: null },
      dmarc: { found: false, record: null, policy: null, pct: null },
      bimi:  { found: false, record: null, hasVmc: false, vmcUrl: null },
      smtp:  { ok: false, error: null },
    };

    const [mxR, txtR, dmarcR, bimiR] = await Promise.allSettled([
      dnsPromises.resolveMx(domain),
      dnsPromises.resolveTxt(domain),
      dnsPromises.resolveTxt(`_dmarc.${domain}`),
      dnsPromises.resolveTxt(`default._bimi.${domain}`),
    ]);

    if (mxR.status === 'fulfilled' && mxR.value.length > 0) {
      result.mx.found = true;
      result.mx.records = mxR.value.sort((a, b) => a.priority - b.priority).slice(0, 5);
    }
    if (txtR.status === 'fulfilled') {
      const spf = txtR.value.flat().find(r => r.startsWith('v=spf1'));
      if (spf) { result.spf.found = true; result.spf.record = spf; }
    }
    if (dmarcR.status === 'fulfilled') {
      const dmarc = dmarcR.value.flat().find(r => r.startsWith('v=DMARC1'));
      if (dmarc) {
        result.dmarc.found = true; result.dmarc.record = dmarc;
        result.dmarc.policy = dmarc.match(/\bp=([a-z]+)/i)?.[1] ?? null;
        const pct = dmarc.match(/\bpct=(\d+)/i);
        result.dmarc.pct = pct ? parseInt(pct[1], 10) : null;
      }
    }
    if (bimiR.status === 'fulfilled') {
      const bimi = bimiR.value.flat().find(r => r.startsWith('v=BIMI1'));
      if (bimi) {
        result.bimi.found = true; result.bimi.record = bimi;
        const aField = bimi.match(/\ba=([^;]+)/i);
        if (aField && aField[1].trim()) {
          result.bimi.hasVmc = true; result.bimi.vmcUrl = aField[1].trim();
        }
      }
    }

    const DKIM_SELECTORS = [
      'google', 'default', 'selector1', 'selector2', 'k1', 'k2', 'k3',
      'mail', 'dkim', 'smtp', 'email', 's1', 's2',
      // Zoho
      'zoho', 'zmail', 'zm1', 'zm2', '1024', '2048',
      // Other providers
      'protonmail', 'protonmail2', 'protonmail3',
      'amazonses', 'postmark', 'mandrill', 'cm', 'mimecast',
      'dkim2', 'sig1', 'everlytickey1', 'everlytickey2',
    ];
    const dkimResults = await Promise.allSettled(
      DKIM_SELECTORS.map(async selector => {
        const txt = await dnsPromises.resolveTxt(`${selector}._domainkey.${domain}`);
        const record = txt.flat().join('');
        if (record.includes('v=DKIM1') || (record.includes('p=') && record.includes('k='))) return { selector, record };
        throw new Error('no_match');
      })
    );
    const firstDkim = dkimResults.find(r => r.status === 'fulfilled');
    if (firstDkim?.status === 'fulfilled') {
      const { selector, record } = firstDkim.value;
      result.dkim.found = true; result.dkim.selector = selector;
      result.dkim.record = record.length > 120 ? record.slice(0, 120) + '…' : record;
    }

    if (result.mx.found && password) {
      try {
        const secure = protocol === 'ssl_tls';
        const transport = nodemailer.createTransport({
          host: smtpHost, port: Number(port) || 465, secure,
          auth: { user: String(username), pass: String(password) },
          connectionTimeout: 8000, greetingTimeout: 8000, socketTimeout: 8000,
          tls: { rejectUnauthorized: false },
        });
        await transport.verify();
        result.smtp.ok = true;
      } catch (e) {
        result.smtp.error = e.code ?? e.responseCode?.toString() ?? 'connection_failed';
      }
    } else if (!result.mx.found) {
      result.smtp.error = 'no_mx_records';
    }

    res.json(result);
  });

  // ── Setup OTP endpoints ────────────────────────────────────────────────────
  app.post('/api/auth/send-setup-otp', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { toEmail } = req.body ?? {};
    if (typeof toEmail !== 'string' || !toEmail.includes('@') || toEmail.length > 320) {
      return res.status(400).json({ error: 'invalid_input' });
    }

    const now  = Date.now();
    const prev = _setupOtps.get(req.user.id);

    if (prev?.lastSentAt && now - prev.lastSentAt < 30_000) {
      return res.status(429).json({ error: 'resend_too_soon', waitMs: 30_000 - (now - prev.lastSentAt) });
    }

    const windowStart = (!prev || now - prev.windowStart > 10 * 60_000) ? now : prev.windowStart;
    const sendCount   = (!prev || now - prev.windowStart > 10 * 60_000) ? 0 : (prev.sendCount ?? 0);
    if (sendCount >= 5) {
      return res.status(429).json({ error: 'rate_limited', waitMs: 10 * 60_000 - (now - windowStart) });
    }

    const code = randomInt(0, 1_000_000).toString().padStart(6, '0');
    _setupOtps.set(req.user.id, {
      code, email: toEmail,
      expires: now + 5 * 60_000, attempts: 0,
      sendCount: sendCount + 1, windowStart, lastSentAt: now,
    });

    const smtpCfg = readUserBlob(req.user.id, 'smtp_config', null);
    try {
      const setupCtx = {
        ip: getClientIp(req),
        userAgent: req.headers['user-agent'] || '',
        browserHint: typeof req.body?.browser === 'string' ? req.body.browser : '',
      };
      const sent = await sendOtpEmail(smtpCfg, toEmail, code, 'setup', setupCtx);
      if (!sent) return res.status(503).json({ error: 'smtp_not_configured' });
      res.json({ ok: true, sendsLeft: 5 - (sendCount + 1) });
    } catch (e) {
      console.error('[setup-otp] send failed:', e.message);
      res.status(502).json({ error: 'smtp_send_failed', detail: e.message });
    }
  });

  const SETUP_OTP_MAX_ATTEMPTS = 3;
  app.post('/api/auth/verify-setup-otp', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const { code } = req.body ?? {};
    if (typeof code !== 'string') return res.status(400).json({ error: 'invalid_input' });

    const entry = _setupOtps.get(req.user.id);
    if (!entry || Date.now() > entry.expires) {
      _setupOtps.delete(req.user.id);
      return res.status(401).json({ ok: false, error: 'expired_or_invalid' });
    }

    const submitted = Buffer.from(code.replace(/\s/g, '').padEnd(6, ' '));
    const stored    = Buffer.from(entry.code.padEnd(6, ' '));
    const match     = submitted.length === stored.length && timingSafeEqual(submitted, stored);

    if (!match) {
      const attempts = (entry.attempts ?? 0) + 1;
      if (attempts >= SETUP_OTP_MAX_ATTEMPTS) {
        _setupOtps.delete(req.user.id);
        return res.status(401).json({ ok: false, error: 'too_many_attempts' });
      }
      _setupOtps.set(req.user.id, { ...entry, attempts });
      return res.status(401).json({ ok: false, error: 'invalid_code', attemptsLeft: SETUP_OTP_MAX_ATTEMPTS - attempts });
    }

    _setupOtps.delete(req.user.id);
    res.json({ ok: true, email: entry.email });
  });
}
