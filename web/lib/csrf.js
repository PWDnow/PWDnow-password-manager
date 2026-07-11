// CSRF middleware.
// Defines COOKIE_CSRF inline (same value as in session.js) to avoid a circular
// import between session.js and csrf.js.
import { timingSafeEqual } from 'crypto';

const COOKIE_CSRF = '_pwd_csrf';

export function requireCsrf(req, res, next) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  const header = req.headers['x-csrf-token'];
  const cookie = req.cookies?.[COOKIE_CSRF];
  if (!header || !cookie || typeof header !== 'string' || typeof cookie !== 'string') {
    return res.status(403).json({ error: 'csrf' });
  }
  const headerBuf = Buffer.from(header);
  const cookieBuf = Buffer.from(cookie);
  if (headerBuf.length !== cookieBuf.length || !timingSafeEqual(headerBuf, cookieBuf)) {
    return res.status(403).json({ error: 'csrf' });
  }
  next();
}
