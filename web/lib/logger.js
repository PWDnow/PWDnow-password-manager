import pino from 'pino';
import pinoHttp from 'pino-http';
import { randomBytes } from 'crypto';

// ── Structured Logger ─────────────────────────────────────────────────────────
// In production: JSON output piped to stdout (collected by PM2 / journald).
// In development: human-readable pretty-print.
//
// Every log line carries at minimum: { time, level, reqId, msg }.
// Security-relevant lines additionally carry: { userId, ip, action }.

const IS_PROD = process.env.NODE_ENV === 'production';

export const logger = pino({
  level: process.env.LOG_LEVEL || (IS_PROD ? 'info' : 'debug'),
  // Redact fields that should never appear in logs, even in dev.
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'req.body.password',
      'req.body.oldPassword',
      'req.body.newPassword',
      'req.body.recoveryKey',
      'req.body.totpCode',
      'req.body.emailCode',
      '*.passwordHash',
      '*.mfaTotpSecret',
    ],
    censor: '[REDACTED]',
  },
  ...(IS_PROD
    ? {}
    : {
        transport: {
          target: 'pino-pretty',
          options: { colorize: true, translateTime: 'SYS:standard', ignore: 'pid,hostname' },
        },
      }),
});

// ── Request correlation ID generator ─────────────────────────────────────────
// Each inbound request gets a unique ID attached to the logger child and sent
// back in the X-Request-ID response header. Downstream services inherit it via
// forwarded headers.
export function generateReqId(req) {
  // Honour an upstream-provided ID (e.g. from Nginx $request_id) so log lines
  // across the proxy and app layer share the same correlation key.
  return req.headers['x-request-id'] || randomBytes(8).toString('hex');
}

// ── pino-http middleware ──────────────────────────────────────────────────────
// Attaches `req.log` (a child logger with reqId) to every request.
// Emits an access log line on response finish with: method, url, statusCode,
// responseTime, and all standard pino-http fields.
export const httpLogger = pinoHttp({
  logger,
  genReqId: generateReqId,
  // Serialisers strip the raw Node IncomingMessage down to safe fields only.
  serializers: {
    req(req) {
      return {
        id:     req.id,
        method: req.method,
        url:    req.url,
        // Omit full headers — only emit the ones useful for diagnostics.
        remoteAddress: req.remoteAddress,
        userAgent: req.headers?.['user-agent'],
      };
    },
    res(res) {
      return { statusCode: res.statusCode };
    },
  },
  // Suppress noisy health/metrics probes from the access log in production.
  autoLogging: {
    ignore(req) {
      return IS_PROD && (req.url === '/health' || req.url === '/metrics');
    },
  },
  // Map HTTP status codes to log levels so 5xx errors are visible as `error`.
  customLogLevel(_req, res, err) {
    if (err || res.statusCode >= 500) return 'error';
    if (res.statusCode >= 400) return 'warn';
    return 'info';
  },
});

// ── Convenience child-logger factory ─────────────────────────────────────────
// Usage: const log = childLogger(req, { userId: u.id });
// Produces a child with the request's correlation ID + any extra bindings.
export function childLogger(req, bindings = {}) {
  const base = req?.log ?? logger;
  return base.child(bindings);
}
