import { randomBytes, timingSafeEqual } from 'crypto';
import { z } from 'zod';
import { ctx } from '../../lib/context.js';
import { hashEmail, withUserDirLock } from '../../lib/fileCrypto.js';
import { issueJwt, setSessionCookies, authMiddleware, requireAuth, saveSessions, getClientIp, recordSession } from '../../lib/session.js';
import { requireCsrf } from '../../lib/csrf.js';
import { appendAuditEvent, compactIpInfo } from '../../lib/audit.js';
import { checkLoginRate, checkHintsRate, checkAccountRate, recordAccountFailure, resetAccountFailures, checkFingerprintRate, recordFingerprintFailure, resetFingerprintFailures, deriveClientIdentity, makeFingerprintLogEntry, mergeFingerprintLog, getDummyArgon2Hash } from '../../lib/rateLimiter.js';
import { getEnvSmtpConfig } from '../../lib/smtpConfig.js';
import * as utils from './utils.js';
const { hashPassword, verifyPassword, isMfaLocked, recordMfaFailure, clearMfaFailure, issueMfaToken, consumeMfaToken, storeEmailOtp, consumeEmailOtp, verifyTotpCode, sendOtpEmail, readUserBlob, performServerWipe } = utils;

export function mountLoginRoutes(app) {
  app.post('/api/auth/login-hints', async (req, res) => {
    const { email, hints } = req.body || {};

    // ── Update hints (Authenticated path) ────────────────────────────────────
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
            const found = await ctx.vaultRepository.updateUserById(req.user.id, (u) => {
              u.loginHints = sanitized;
            });
            if (found === null) return res.status(401).json({ error: 'user_not_found' });
            return res.json({ ok: true });
          });
        });
      });
    }

    // ── Read hints (Unauthenticated path) ───────────────────────────────────
    if (!await checkHintsRate(getClientIp(req))) {
      return res.status(429).json({ error: 'too_many_requests' });
    }

    if (typeof email !== 'string') return res.status(400).json({ error: 'invalid_input' });
    const emailHash = hashEmail(email);
    const u = await ctx.vaultRepository.findUserByEmailHash(emailHash);

    // V-26-04 Fix: Always return a uniform structure to prevent user enumeration.
    // Registered and unregistered users must be indistinguishable here.
    const defaults = { 
      totp: false, 
      emailOtp: false, 
      passwordEnabled: true, 
      webauthn: false, 
      passwordlessEnabled: false 
    };

    if (!u || !u.loginHints) {
      // For non-existent users, we return the same defaults.
      // To prevent timing oracles, we could add a tiny random jitter, 
      // but a uniform response is the primary defense.
      return res.json({ hints: defaults });
    }

    // For existent users, we filter their hints through the same safe default schema.
    const rawHints = u.loginHints || {};
    const safeHints = {};
    for (const k of Object.keys(defaults)) {
      if (typeof rawHints[k] === 'boolean') {
        safeHints[k] = rawHints[k];
      } else {
        safeHints[k] = defaults[k];
      }
    }
    return res.json({ hints: safeHints });
  });

  app.post('/api/auth/crypto-salt', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { cryptoSalt } = req.body || {};
    if (typeof cryptoSalt !== 'string' || !/^[0-9a-f]{32}$/i.test(cryptoSalt)) {
      return res.status(400).json({ error: 'invalid_salt' });
    }
    let finalSalt = null;
    let stored = false;
    const found = await ctx.vaultRepository.updateUserById(req.user.id, (u) => {
      if (!u.cryptoSalt) {
        u.cryptoSalt = cryptoSalt;
        stored = true;
      }
      finalSalt = u.cryptoSalt;
    });
    if (found === null) return res.status(401).json({ error: 'user_not_found' });
    if (stored && process.env.NODE_ENV !== 'production') {
      console.log(`[auth] Stored cryptoSalt for user ${req.user.id}`);
    }
    if (finalSalt) res.setHeader('X-Vault-Salt', finalSalt);
    res.json({ ok: true });
  });

  app.post('/api/auth/login', authMiddleware, async (req, res) => {
    const loginSchema = z.object({
      email: z.string().email().max(320),
      password: z.string().min(1).max(128),
      fingerprint: z.any().optional()
    });
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'invalid_input' });
    }
    const { email, password, fingerprint } = parsed.data;
    const emailHash = hashEmail(email);

    const uSnapshot = await ctx.vaultRepository.findUserByEmailHash(emailHash);
    const duressArmed = !!(uSnapshot && uSnapshot.duressEnforce && uSnapshot.duressEnforce.armed);

    const clientIdentity = deriveClientIdentity(req, fingerprint);

    const [ipBlocked, fpBlocked, accountBlocked] = await Promise.all([
      checkLoginRate(getClientIp(req)).then(ok => !ok),
      checkFingerprintRate(clientIdentity).then(ok => !ok),
      duressArmed ? Promise.resolve(false) : checkAccountRate(emailHash).then(ok => !ok),
    ]);
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
      const failOps = [recordFingerprintFailure(clientIdentity)];
      if (!duressArmed) failOps.push(recordAccountFailure(emailHash));
      await Promise.all(failOps);

      if (uSnapshot) {
        await ctx.vaultRepository.updateUserById(uSnapshot.id, (fu) => {
          const fpEntry = makeFingerprintLogEntry(clientIdentity, fingerprint, req, false);
          fu.fingerprintLog = mergeFingerprintLog(fu.fingerprintLog, fpEntry);
        });
      }

      let duressRemaining = null;
      let duressWipe = false;
      if (uSnapshot && duressArmed) {
        await ctx.vaultRepository.updateUserById(uSnapshot.id, (fu) => {
          if (!fu.duressEnforce || !fu.duressEnforce.armed) return false;
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
    await Promise.all([resetAccountFailures(emailHash), resetFingerprintFailures(clientIdentity)]);

    let finalU = null;
    await ctx.vaultRepository.updateUserById(uSnapshot.id, (fu) => {
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

    const mfaCfg = await readUserBlob(u.id, 'mfa_config', {});
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
      if (await isMfaLocked(u.id)) {
        return res.status(429).json({ ok: false, error: 'mfa_locked' });
      }
      const partialToken = await issueMfaToken(u.id);
      if (mfaMethods.includes('email')) {
        const otp = await storeEmailOtp(partialToken);
        const profile  = await readUserBlob(u.id, 'profile', { email: '' });
        const smtpCfg  = (await readUserBlob(u.id, 'smtp_config', null)) ?? getEnvSmtpConfig();
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

    const u = await ctx.vaultRepository.findUserById(userId);
    if (!u) return res.status(401).json({ ok: false, error: 'user_not_found' });

    const mfaEnforce = u.mfaEnforce || {};

    if (await isMfaLocked(u.id)) {
      return res.status(429).json({ ok: false, error: 'mfa_locked' });
    }

    if (mfaEnforce.totp && u.mfaTotpSecret) {
      const code = totpCode ?? emailCode;
      if (typeof code !== 'string') return res.status(401).json({ ok: false, error: 'mfa_required' });
      if (!await verifyTotpCode(u.mfaTotpSecret, code)) {
        await recordMfaFailure(u.id);
        appendAuditEvent(u.id, { action: 'mfa_failed', ip: getClientIp(req), success: false });
        return res.status(401).json({ ok: false, error: 'invalid_mfa_code' });
      }
    } else if (mfaEnforce.email) {
      if (typeof emailCode !== 'string') {
        return res.status(401).json({ ok: false, error: 'mfa_required' });
      }
      const stored = await consumeEmailOtp(partialToken);
      if (!stored) {
        await recordMfaFailure(u.id);
        appendAuditEvent(u.id, { action: 'mfa_failed', ip: getClientIp(req), success: false });
        return res.status(401).json({ ok: false, error: 'invalid_mfa_code' });
      }
      const supplied = emailCode.trim().slice(0, 8);
      const match = supplied.length === stored.length &&
        timingSafeEqual(Buffer.from(supplied), Buffer.from(stored));
      if (!match) {
        await recordMfaFailure(u.id);
        appendAuditEvent(u.id, { action: 'mfa_failed', ip: getClientIp(req), success: false });
        return res.status(401).json({ ok: false, error: 'invalid_mfa_code' });
      }
    }

    await clearMfaFailure(u.id);
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

    const uSnap = await ctx.vaultRepository.findUserById(req.user.id);
    if (!uSnap) return res.status(401).json({ error: 'user_not_found' });

    const verified = await verifyPassword(uSnap.passwordHash, password, uSnap.salt);
    if (!verified) return res.status(401).json({ error: 'invalid_password' });

    const hash = await hashPassword(recoveryKey);

    const found = await ctx.vaultRepository.updateUserById(req.user.id, (u) => {
      if (u.passwordHash !== uSnap.passwordHash) {
        throw Object.assign(new Error('password_changed_concurrently'), { status: 409 });
      }
      u.recoveryKeyHash = hash;
      u.recoveryKeySalt = null;
      u.recoveryKeyGeneratedAt = Date.now();
      u.recoveryKeyExpiresAt = Date.now() + 90 * 24 * 60 * 60 * 1000;
    }).catch(err => {
      if (err && err.status === 409) {
        res.status(409).json({ error: 'password_changed' });
        return 'handled';
      }
      throw err;
    });
    if (found === 'handled') return;
    if (found === null) return res.status(401).json({ error: 'user_not_found' });
    res.json({ ok: true });
  });

  app.get('/api/auth/fingerprints', authMiddleware, requireAuth, async (req, res) => {
    const u = await ctx.vaultRepository.findUserById(req.user.id);
    if (!u) return res.status(401).json({ error: 'user_not_found' });
    const list = Array.isArray(u.fingerprintLog) ? u.fingerprintLog : [];
    res.json({ ok: true, fingerprints: list.slice().sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0)) });
  });

  app.delete('/api/auth/fingerprints/:id', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const targetId = String(req.params.id || '');
    if (!/^[0-9a-f]{4,128}$/i.test(targetId)) return res.status(400).json({ error: 'invalid_id' });
    const found = await ctx.vaultRepository.updateUserById(req.user.id, (u) => {
      const log = Array.isArray(u.fingerprintLog) ? u.fingerprintLog : [];
      const before = log.length;
      u.fingerprintLog = log.filter(e => e.id !== targetId);
      if (u.fingerprintLog.length === before) return false;
    });
    if (found === null || found === false) return res.status(404).json({ error: 'not_found' });
    await resetFingerprintFailures(targetId);
    res.json({ ok: true });
  });

  app.post('/api/auth/verify-password', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!await checkLoginRate(getClientIp(req))) {
      return res.status(429).json({ error: 'too_many_requests' });
    }
    try {
      const { password } = req.body || {};
      if (typeof password !== 'string') return res.status(400).json({ error: 'invalid_input' });
      const u = await ctx.vaultRepository.findUserById(req.user.id);
      if (!u) return res.status(401).json({ error: 'user_not_found' });
      if (await isMfaLocked(u.id)) return res.status(429).json({ ok: false, error: 'too_many_attempts' });
      const authenticated = await verifyPassword(u.passwordHash, password, u.salt);
      if (!authenticated) {
        await recordMfaFailure(u.id);
        return res.json({ ok: false });
      }
      await clearMfaFailure(u.id);
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

    const uSnap = await ctx.vaultRepository.findUserById(req.user.id);
    if (!uSnap) return res.status(401).json({ error: 'user_not_found' });

    const authenticated = await verifyPassword(uSnap.passwordHash, oldPassword, uSnap.salt);
    if (!authenticated) return res.status(401).json({ error: 'invalid_credentials' });

    const newHash = await hashPassword(newPassword);

    const found = await ctx.vaultRepository.updateUserById(req.user.id, (u) => {
      if (u.passwordHash !== uSnap.passwordHash) {
        throw Object.assign(new Error('password_changed_concurrently'), { status: 409 });
      }
      u.salt = null;
      u.passwordHash = newHash;
      u.passwordChangedAt = Date.now();
      u.revocationEpoch = (Number(u.revocationEpoch) || 0) + 1;
    }).catch(err => {
      if (err && err.status === 409) {
        res.status(409).json({ error: 'password_changed' });
        return 'handled';
      }
      throw err;
    });
    if (found === 'handled') return;
    if (found === null) return res.status(401).json({ error: 'user_not_found' });

    await withUserDirLock(req.user.id, async () => {
      await ctx.vaultRepository.saveSessions(req.user.id, []);
    });

    appendAuditEvent(req.user.id, { action: 'password_changed', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true });
  });

  
}
