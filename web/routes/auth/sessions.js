import { ctx } from '../../lib/context.js';
import { withUserDirLock } from '../../lib/fileCrypto.js';
import { clearSessionCookies, authMiddleware, requireAuth, loadSessions, saveSessions, getClientIp } from '../../lib/session.js';
import { requireCsrf } from '../../lib/csrf.js';
import { appendAuditEvent, compactIpInfo, getServerPublicIp } from '../../lib/audit.js';
import * as utils from './utils.js';
const { readUserBlob } = utils;

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
