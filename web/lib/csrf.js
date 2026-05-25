// CSRF middleware.
// Defines COOKIE_CSRF inline (same value as in session.js) to avoid a circular
// import between session.js and csrf.js.

const COOKIE_CSRF = '_pwd_csrf';

export function requireCsrf(req, res, next) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  const header = req.headers['x-csrf-token'];
  const cookie = req.cookies?.[COOKIE_CSRF];
  if (!header || !cookie || typeof header !== 'string' || header !== cookie) {
    return res.status(403).json({ error: 'csrf' });
  }
  next();
}
