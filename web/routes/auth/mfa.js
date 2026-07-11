import { randomBytes, randomInt, timingSafeEqual, scryptSync, pbkdf2, createHash } from 'crypto';
import { promisify } from 'util';
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync, openSync, writeSync, fsyncSync, closeSync } from 'fs';
import { promises as dnsPromises } from 'dns';
import nodemailer from 'nodemailer';
import { lock } from 'proper-lockfile';
import argon2 from 'argon2';
import { TOTP } from 'totp-generator';
import path from 'path';
import { z } from 'zod';
import { ctx } from '../../lib/context.js';
import { logger } from '../../lib/logger.js';
import { decryptBlob, readEncryptedFile, writeEncryptedFile, userVaultFile, userInfo, userVaultDir, loadUsers, hashEmail, withUsersLock, withUserDirLock } from '../../lib/fileCrypto.js';
import { issueJwt, setSessionCookies, clearSessionCookies, authMiddleware, requireAuth, loadSessions, saveSessions, generateUUID, getClientIp, recordSession } from '../../lib/session.js';
import { requireCsrf } from '../../lib/csrf.js';
import { appendAuditEvent, compactIpInfo, getServerPublicIp } from '../../lib/audit.js';
import { checkLoginRate, checkHintsRate, checkRegisterRate, checkRegisterEmailRate, checkAccountRate, recordAccountFailure, resetAccountFailures, checkFingerprintRate, recordFingerprintFailure, resetFingerprintFailures, checkDnsRate, deriveClientIdentity, deriveLockoutIdentity, lockoutIdentityFromLogEntry, makeFingerprintLogEntry, mergeFingerprintLog, getDummyArgon2Hash, ARGON2_MEMORY_KIB, ARGON2_TIME_COST, ARGON2_PARALLELISM, ARGON2_MAX_CONCURRENT, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_LEN, SCRYPT_MAXMEM, PBKDF2_SHA512_ITERS, PBKDF2_SHA512_LEN, PBKDF2_HASH_PREFIX } from '../../lib/rateLimiter.js';
import { getEnvSmtpConfig, parseSmtpTestFilter } from '../../lib/smtpConfig.js';
import { resolvesToPublicHost } from '../../lib/ssrfGuard.js';
import * as utils from './utils.js';
const { pbkdf2Async, scryptHash, constEq, MFA_MAX_ATTEMPTS, PARTIAL_MFA_TTL_MS, mfaPendingPath, saveMfaPending, _usedTotpPeriods, _setupOtps, _parseBrowserFromUA, _parseOSFromUA, _escHtml, sendOtpEmail, readUserBlob, writeUserBlob, readUserBlobAsync, writeUserBlobAsync, secureOverwriteDir } = utils;

export function mountMfaRoutes(app) {
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

    const smtpCfg = (await readUserBlob(req.user.id, 'smtp_config', null)) ?? getEnvSmtpConfig();
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

  const SETUP_OTP_MAX_ATTEMPTS = process.env.SETUP_OTP_MAX_ATTEMPTS ? parseInt(process.env.SETUP_OTP_MAX_ATTEMPTS, 10) : 3;
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
