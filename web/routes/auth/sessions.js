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
const { pbkdf2Async, scryptHash, constEq, MFA_MAX_ATTEMPTS, PARTIAL_MFA_TTL_MS, mfaPendingPath, saveMfaPending, _usedTotpPeriods, _setupOtps, _parseBrowserFromUA, _parseOSFromUA, _escHtml, readUserBlob, writeUserBlob, readUserBlobAsync, writeUserBlobAsync, secureOverwriteDir } = utils;

export function mountSessionsRoutes(app) {
  app.get('/api/auth/me', authMiddleware, async (req, res) => {
    if (!req.user) return res.json({ authenticated: false });
    const u = await ctx.vaultRepository.findUserById(req.user.id);
    if (!u) return res.json({ authenticated: false });
    const profile = await readUserBlob(u.id, 'profile', { firstName: '', lastName: '', email: '' });
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

  
  app.get('/api/auth/sessions', authMiddleware, requireAuth, async (req, res) => {
    const list = (await ctx.vaultRepository.loadSessions(req.user.id))
      .slice()
      .sort((a, b) => b.timestamp - a.timestamp)
      .map(({ jti: _jti, ...rest }) => rest);
    res.json(list);
  });

  app.post('/api/auth/sessions/revoke-others', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    await ctx.vaultRepository.updateUserById(req.user.id, (u) => {
      u.revocationEpoch = (Number(u.revocationEpoch) || 0) + 1;
    });
    await withUserDirLock(req.user.id, async () => {
      const list = (await ctx.vaultRepository.loadSessions(req.user.id)).filter(s => s.jti === req.user.jti);
      await ctx.vaultRepository.saveSessions(req.user.id, list);
    });
    res.json({ ok: true });
  });

  app.post('/api/auth/logout', authMiddleware, requireCsrf, async (req, res) => {
    if (req.user) {
      await withUserDirLock(req.user.id, async () => {
        const list = (await ctx.vaultRepository.loadSessions(req.user.id)).filter(s => s.jti !== req.user.jti);
        await ctx.vaultRepository.saveSessions(req.user.id, list);
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
  
}
