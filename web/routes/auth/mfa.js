import { randomInt, timingSafeEqual } from 'crypto';
import { logger } from '../../lib/logger.js';
import { authMiddleware, requireAuth, getClientIp } from '../../lib/session.js';
import { requireCsrf } from '../../lib/csrf.js';
import { getEnvSmtpConfig } from '../../lib/smtpConfig.js';
import * as utils from './utils.js';
const { _setupOtps, sendOtpEmail, readUserBlob } = utils;

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
      logger.error({ err: e.message }, '[setup-otp] send failed');
      res.status(502).json({ error: 'smtp_send_failed' });
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
