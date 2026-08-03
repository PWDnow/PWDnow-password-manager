import { randomBytes } from 'crypto';
import { z } from 'zod';
import { ctx } from '../../lib/context.js';
import { hashEmail } from '../../lib/fileCrypto.js';
import { issueJwt, setSessionCookies, authMiddleware, getClientIp, recordSession } from '../../lib/session.js';
import { checkRegisterRate } from '../../lib/rateLimiter.js';
import * as utils from './utils.js';
const { hashPassword, writeUserBlob } = utils;

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
