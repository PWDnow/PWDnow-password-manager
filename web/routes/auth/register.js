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
const { pbkdf2Async, scryptHash, constEq, hashPassword, verifyPassword, MFA_MAX_ATTEMPTS, PARTIAL_MFA_TTL_MS, mfaPendingPath, saveMfaPending, _usedTotpPeriods, _setupOtps, _parseBrowserFromUA, _parseOSFromUA, _escHtml, readUserBlob, writeUserBlob, readUserBlobAsync, writeUserBlobAsync, secureOverwriteDir } = utils;

export function mountRegisterRoutes(app) {
  app.post('/api/auth/register', authMiddleware, async (req, res) => {
    if (!await checkRegisterRate(getClientIp(req))) {
      return res.status(429).json({ error: 'too_many_requests' });
    }
    const registerSchema = z.object({
      email: z.string().email().max(320),
      password: z.string().min(12).max(128),
      firstName: z.string().min(1).max(100),
      lastName: z.string().min(1).max(100),
      cryptoSalt: z.string().optional()
    });
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'invalid_input' });
    }
    const { email, password, firstName, lastName, cryptoSalt } = parsed.data;

    const emailHash = hashEmail(email);
    if (await ctx.vaultRepository.findUserByEmailHash(emailHash)) {
      return res.status(409).json({ error: 'email_taken' });
    }

    let hash;
    try { hash = await hashPassword(password); }
    catch (e) { return res.status(e.status || 500).json({ error: e.message }); }
    const id = randomBytes(16).toString('hex');

    try {
      await ctx.vaultRepository.insertUser({ id, emailHash, passwordHash: hash, salt: null, cryptoSalt: cryptoSalt || null, createdAt: Date.now() });
    } catch (e) {
      if (e.code === 'USER_EXISTS') return res.status(409).json({ error: 'email_taken' });
      throw e;
    }
    await writeUserBlob(id, 'profile', { firstName, lastName, email: email.trim() });
    await writeUserBlob(id, 'credentials', []);
    await writeUserBlob(id, 'folders', []);
    await writeUserBlob(id, 'asset_holder', { emails: [], phoneNumbers: [], u2fKeys: [] });

    const { token, jti } = await issueJwt(id);
    const csrf = randomBytes(24).toString('hex');
    setSessionCookies(req, res, token, csrf);
    await recordSession(id, jti, req);
    res.json({ ok: true });
  });

  
}
