import express from 'express';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import { readFileSync, writeFileSync, existsSync, statSync } from 'fs';
import { randomBytes, timingSafeEqual, createHash } from 'crypto';
import { execFile } from 'child_process';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { register as promRegister, collectDefaultMetrics, Counter, Gauge, Histogram } from 'prom-client';
import { createServer as createHttpServer } from 'http';
import { createServer as createHttpsServer } from 'https';
import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';
import { initAuth, mountAuthAndVault, getServerPublicIp } from './auth.js';
import { checkRpcRate, checkDnsRate, checkSetupExecRate } from './lib/rateLimiter.js';
import { promises as dnsPromises } from 'dns';
import { logger, httpLogger } from './lib/logger.js';

dotenv.config();

// Fail closed if NODE_ENV is not explicitly set. Defaulting to 'development'
// silently enables verbose logging in production-like launchers (CWE-209).
if (!process.env.NODE_ENV) {
  throw new Error('NODE_ENV must be set explicitly (set to "production" in production launchers)');
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.disable('x-powered-by');
const PORT = parseInt(process.env.PORT || '1234', 10);
const BIND_HOST = process.env.BIND_HOST || '127.0.0.1';
// The daemon now exposes gRPC (Phase 1 of the horizontal-scalability migration)
// instead of a Unix domain socket. Default to loopback; override for a remote
// daemon pod in distributed deployments.
const DAEMON_GRPC_ADDR = process.env.DAEMON_GRPC_ADDR || '127.0.0.1:50051';

// Guard: in production, nginx proxies to port 1234 — a mismatch causes 502.
if (process.env.NODE_ENV === 'production' && PORT !== 1234) {
  logger.warn({ port: PORT, expected: 1234 }, 'PORT mismatch: nginx upstream expects 1234 — this will cause 502 Bad Gateway');
}
const IS_PROD = process.env.NODE_ENV === 'production';

// ── SSL / HTTPS configuration ─────────────────────────────────────────────────
// SSL=false → plain HTTP (default); SSL=true → HTTPS only; SSL=force → HTTPS + HTTP redirect
const SSL_MODE = (process.env.SSL || 'false').toLowerCase();
const SSL_DIR  = process.env.SSL_DIR  || (IS_PROD ? '/opt/pwdnow/ssl' : path.join(__dirname, 'ssl'));
const SSL_PORT = parseInt(process.env.SSL_PORT || '51234', 10);

// Prefer ECDSA (faster handshake), fall back to RSA; serve both when present so
// the TLS stack picks the best match per client (dual-cert negotiation).
let tlsOptions = null;
if (SSL_MODE === 'true' || SSL_MODE === 'force') {
  const ecdsaCert = path.join(SSL_DIR, 'ecdsa', 'server.crt');
  const ecdsaKey  = path.join(SSL_DIR, 'ecdsa', 'server.key');
  const rsaCert   = path.join(SSL_DIR, 'rsa',   'server.crt');
  const rsaKey    = path.join(SSL_DIR, 'rsa',   'server.key');

  const hasEcdsa = existsSync(ecdsaCert) && existsSync(ecdsaKey);
  const hasRsa   = existsSync(rsaCert)   && existsSync(rsaKey);
  // Flat layout: a single cert placed directly in SSL_DIR (e.g. self-signed / custom CA certs).
  const flatCert = path.join(SSL_DIR, 'server.crt');
  const flatKey  = path.join(SSL_DIR, 'server.key');
  const hasFlat  = existsSync(flatCert) && existsSync(flatKey);

  if (hasEcdsa && hasRsa) {
    tlsOptions = {
      cert: [readFileSync(ecdsaCert), readFileSync(rsaCert)],
      key:  [readFileSync(ecdsaKey),  readFileSync(rsaKey)],
      minVersion: 'TLSv1.3',
    };
    logger.info({ sslDir: SSL_DIR, mode: 'ecdsa+rsa' }, 'SSL dual-cert loaded');
  } else if (hasEcdsa) {
    tlsOptions = { cert: readFileSync(ecdsaCert), key: readFileSync(ecdsaKey), minVersion: 'TLSv1.3' };
    logger.info({ sslDir: SSL_DIR, mode: 'ecdsa' }, 'SSL cert loaded');
  } else if (hasRsa) {
    tlsOptions = { cert: readFileSync(rsaCert), key: readFileSync(rsaKey), minVersion: 'TLSv1.3' };
    logger.info({ sslDir: SSL_DIR, mode: 'rsa' }, 'SSL cert loaded');
  } else if (hasFlat) {
    tlsOptions = { cert: readFileSync(flatCert), key: readFileSync(flatKey), minVersion: 'TLSv1.2' };
    logger.info({ sslDir: SSL_DIR, mode: 'flat' }, 'SSL cert loaded');
  } else {
    logger.warn({ sslDir: SSL_DIR, sslMode: SSL_MODE, certPath: flatCert, keyPath: flatKey },
      'SSL enabled but no certificates found — run: npm run ssl:generate');
  }
}

// Production data directory is isolated from source code.
const DATA_DIR = process.env.VAULT_DATA_DIR || (IS_PROD ? '/var/lib/vault-server' : path.join(__dirname, 'auth_data'));

// ── Prometheus metrics ────────────────────────────────────────────────────────
collectDefaultMetrics({ prefix: 'pwdnow_' });

export const httpRequestDuration = new Histogram({
  name: 'pwdnow_http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
});

export const authAttempts = new Counter({
  name: 'pwdnow_auth_attempts_total',
  help: 'Total authentication attempts',
  labelNames: ['result'],   // 'ok' | 'fail' | 'rate_limited'
});

// Trust only the loopback interface as a reverse proxy: makes req.ip resolve
// from X-Real-IP (set by Nginx to $remote_addr) and req.secure reflect Nginx
// TLS termination. Without this, both read raw socket values, enabling XFF spoofing.
// Only applied in production — dev connects directly without Nginx.
if (IS_PROD) {
  app.set('trust proxy', 'loopback');
} else {
  app.set('trust proxy', false);
}

// ── Force HTTPS middleware ────────────────────────────────────────────────────
// Redirect HTTP → HTTPS for SSL=force. Localhost health/metrics probes exempted.
if (SSL_MODE === 'force' && tlsOptions) {
  app.use((req, res, next) => {
    if (req.secure) return next();
    if (req.headers['x-forwarded-proto'] === 'https') return next();
    // Exempt loopback health/metrics from redirect
    if (isLocalhost(req) && (req.path === '/health' || req.path === '/metrics')) return next();
    const host = (req.headers.host || req.hostname || 'localhost').replace(/:\d+$/, '');
    const target = `https://${host}${SSL_PORT !== 443 ? `:${SSL_PORT}` : ''}${req.url}`;
    return res.redirect(301, target);
  });
}

await initAuth({ dataDir: DATA_DIR });

// Skip compression on /api/ routes to prevent BREACH/HEIST side-channel attacks
// on authenticated JSON responses. Static assets and SPA HTML are safe to compress.
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  return compression()(req, res, next);
});
app.use(cookieParser());

// Structured HTTP access logging with correlation ID and automatic severity mapping.
app.use(httpLogger);


// ── Setup token ───────────────────────────────────────────────────────────────
// Generated once at startup, held only in memory. Required as X-Setup-Token header
// on every privileged admin endpoint. /api/setup-token is localhost-only, which
// prevents cross-origin pages from obtaining the token (CSRF defence).
const SETUP_TOKEN_BYTES = randomBytes(32);
let SETUP_TOKEN = SETUP_TOKEN_BYTES.toString('hex');

// Trust only the TCP socket address and X-Real-IP (set by Nginx to $remote_addr).
// X-Forwarded-For is intentionally ignored: clients can prepend arbitrary values
// before Nginx appends the real remote IP — trusting it enables IP-spoofing bypass.
// Nginx config must include: proxy_set_header X-Real-IP $remote_addr;
function isLocalhost(req) {
  const socketAddr = req.socket.remoteAddress;
  const socketIsLocal =
    socketAddr === '127.0.0.1' ||
    socketAddr === '::1' ||
    socketAddr === '::ffff:127.0.0.1';

  if (!socketIsLocal) return false;

  // X-Real-IP is overwritten by Nginx to $remote_addr — safe to trust.
  const realIp = req.headers['x-real-ip'];
  if (realIp) {
    return realIp === '127.0.0.1' || realIp === '::1' || realIp === '::ffff:127.0.0.1';
  }

  return true; // direct local connection
}

// Best-effort client IP for rate limiting: trust X-Real-IP only when the
// connection itself terminates at Nginx on localhost (same trust model as
// isLocalhost above).
function clientIp(req) {
  const socketAddr = req.socket.remoteAddress;
  const socketIsLocal =
    socketAddr === '127.0.0.1' || socketAddr === '::1' || socketAddr === '::ffff:127.0.0.1';
  const realIp = req.headers['x-real-ip'];
  if (socketIsLocal && realIp) return realIp;
  return socketAddr || '127.0.0.1';
}

// Localhost + Host + Origin/Referer re-validation, shared by every setup-phase
// route that executes something consequential (vending the token itself, or
// running privileged commands via execFile). A leaked X-Setup-Token alone
// must not be sufficient from a non-local origin — DNS-rebinding guard.
function requireLocalOrigin(req, res, next) {
  if (!isLocalhost(req)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const host = req.headers['host'];
  const localHostRe = /^(localhost|127\.0\.0\.1|::1)(:\d+)?$/i;
  if (!host || !localHostRe.test(host)) {
    return res.status(403).json({ error: 'forbidden: invalid host' });
  }

  const origin = req.headers['origin'];
  const referer = req.headers['referer'];
  const localOriginRe = /^https?:\/\/(localhost|127\.0\.0\.1|::1)(:\d+)?$/i;
  if (origin && !localOriginRe.test(origin)) {
    return res.status(403).json({ error: 'forbidden: invalid origin' });
  }
  if (referer) {
    try {
      if (!localOriginRe.test(new URL(referer).origin)) {
        return res.status(403).json({ error: 'forbidden: invalid referer' });
      }
    } catch {
      return res.status(403).json({ error: 'forbidden: malformed referer' });
    }
  }
  next();
}

function requireSetupToken(req, res, next) {
  const provided = req.headers['x-setup-token'];
  if (!provided || typeof provided !== 'string' || !SETUP_TOKEN) {
    return res.status(403).json({ error: 'Missing X-Setup-Token header' });
  }
  try {
    const providedBuf = Buffer.from(provided, 'hex');
    const tokenBuf = Buffer.from(SETUP_TOKEN, 'hex');
    if (providedBuf.length !== tokenBuf.length ||
        !timingSafeEqual(providedBuf, tokenBuf)) {
      return res.status(403).json({ error: 'Invalid setup token' });
    }
  } catch {
    return res.status(403).json({ error: 'Invalid setup token' });
  }
  next();
}

// ── Per-request CSP nonce middleware ──────────────────────────────────────────
// 'unsafe-inline' is not in the CSP; Vite's inline bootstrap script is instead
// accepted via the per-request nonce injected into index.html.
app.use((req, res, next) => {
  res.locals.cspNonce = randomBytes(16).toString('base64');
  next();
});

app.use((req, res, next) => {
  const nonce = res.locals.cspNonce;
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc:     ["'none'"],
        // 'wasm-unsafe-eval' allows WebAssembly.compile/instantiate only — does NOT
        // re-enable JS eval. Required for Argon2id KDF (hash-wasm) on main thread and
        // kdf.worker.ts. The separate 'unsafe-eval' token is never granted.
        scriptSrc:      ["'self'", `'nonce-${nonce}'`, "'wasm-unsafe-eval'"],
        // Tailwind v4 @tailwindcss/vite emits a static CSS file at build time — no
        // runtime style injection, so 'unsafe-inline' is not needed.
        styleSrc:       ["'self'"],
        fontSrc:        ["'self'"],
        imgSrc:         ["'self'", "blob:"],  // data: removed (exfil vector)
        // WEB-04: 'self' already covers same-origin WS/WSS (the app has none —
        // /ws is defunct, returns 410); a bare ws:/wss: wildcard would let a
        // script-injection open a WebSocket to any host, so it's dropped.
        // pwnedpasswords.com is a live runtime dependency (BreachMonitor.tsx
        // k-anonymity range query), not the offline-only HIBP filter — keep it.
        connectSrc:     ["'self'", "https://api.pwnedpasswords.com"],
        formAction:     ["'self'"],
        frameAncestors: ["'none'"],
        baseUri:        ["'none'"],
        objectSrc:      ["'none'"],
        workerSrc:               ["'self'", "blob:"],
        manifestSrc:             ["'self'"],
        requireTrustedTypesFor:  ["'script'"],
        // allow-duplicates: HMR re-registers the same policy name on hot reload.
        trustedTypes:            ["dompurify", "react-dom", "default", "'allow-duplicates'"],
        upgradeInsecureRequests: null, // Nginx handles HTTPS upgrade at the proxy layer
      },
    },
    strictTransportSecurity: IS_PROD
      ? { maxAge: 31536000, includeSubDomains: true }
      : false,
    // COEP required for SharedArrayBuffer isolation; COOP+COEP = full cross-origin isolation.
    crossOriginEmbedderPolicy: { policy: 'require-corp' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xContentTypeOptions: true,
    xFrameOptions: { action: 'deny' },
  })(req, res, next);
});

// Global JSON body limit is 512 KB. The travel-vault mirror endpoint accepts
// up to 5 MiB of opaque ciphertext, so it uses a route-specific override.
// Nginx's client_max_body_size must be set to 5m to match (deploy/nginx/vault.conf).
const jsonDefault = express.json({ limit: '512kb' });
const jsonTravelVault = express.json({ limit: '5mb' });
app.use((req, res, next) => {
  if (req.path === '/api/vault/travel-vault') return jsonTravelVault(req, res, next);
  return jsonDefault(req, res, next);
});

// Echo the pino-http correlation ID back in the response header so clients
// and downstream services can correlate logs for a specific request.
app.use((req, res, next) => {
  if (req.id) res.setHeader('X-Request-ID', req.id);
  next();
});

// Prevent MIME-sniffing on API JSON responses via Content-Disposition.
// Also set no-store on all API responses so service workers never cache auth data.
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store');
  }
  const origJson = res.json.bind(res);
  res.json = function(body) {
    if (!res.getHeader('Content-Disposition')) {
      res.setHeader('Content-Disposition', 'attachment');
    }
    return origJson(body);
  };
  next();
});

const distPath = path.join(__dirname, 'dist');

// Service workers run in an isolated global scope and cannot call importScripts()
// under require-trusted-types-for 'script'. Intercept sw.js and its Workbox chunk
// before express.static to serve a minimal SW-appropriate CSP instead.
const SW_CSP = "default-src 'self'; script-src 'self'";
app.get('/sw.js', (_req, res) => {
  res.setHeader('Content-Security-Policy', SW_CSP);
  res.setHeader('Cache-Control', 'public, max-age=0');
  res.setHeader('Service-Worker-Allowed', '/');
  res.sendFile(path.join(distPath, 'sw.js'));
});
app.get(/^\/workbox-[0-9a-f]+\.js$/, (req, res) => {
  res.setHeader('Content-Security-Policy', SW_CSP);
  res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
  res.sendFile(path.join(distPath, req.path.slice(1)));
});
// Content-hashed assets are immutable — cache for 1 year.
app.use('/assets', express.static(path.join(distPath, 'assets'), {
  index: false,
  maxAge: '1y',
  immutable: true,
}));

// Return a reload script for missing JS assets instead of 404.
// Fixes the white-screen issue when a stale index.html requests old content-hashed assets.
app.use('/assets', (req, res) => {
  if (req.path.endsWith('.js')) {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'no-store');
    return res.send(`
      console.warn("Stale asset requested. Forcing update.");
      if ('serviceWorker' in navigator) {
        navigator.serviceWorker.getRegistrations().then(regs => {
          for (let r of regs) r.update();
        });
      }
      setTimeout(() => window.location.reload(), 1000);
    `);
  }
  res.status(404).send('Asset not found');
});

app.use(express.static(distPath, { index: false }));

// SPA fallback: inject per-request CSP nonce into index.html before serving.
// Vite emits a small inline <script> for module preloading; we add the nonce so
// the browser accepts it without 'unsafe-inline'.
const indexHtmlPath = path.join(distPath, 'index.html');

// Compute SRI (sha384) hashes for all referenced assets and inject integrity= attributes.
// Done at startup (and invalidated on mtime change) rather than per-request.
function computeSriForAssets(htmlStr, assetDir) {
  return htmlStr.replace(
    /((?:src|href)="(\/assets\/[^"]+)")/g,
    (match, attr, assetPath) => {
      const filePath = path.join(assetDir, assetPath.replace(/^\/assets\//, ''));
      try {
        const content = readFileSync(filePath);
        const hash = createHash('sha384').update(content).digest('base64');
        const integrityAttr = `integrity="sha384-${hash}"`;
        return attr.includes('integrity') ? match : `${attr} ${integrityAttr}`;
      } catch { return match; }
    }
  );
}
let _sriHtml = null;
let _sriHtmlMtime = 0;

function getSriHtml() {
  try {
    const stats = statSync(indexHtmlPath);
    const mtime = stats.mtimeMs;

    if (!_sriHtml || mtime > _sriHtmlMtime) {
      const raw = readFileSync(indexHtmlPath, 'utf-8');
      _sriHtml = computeSriForAssets(raw, distPath);
      _sriHtmlMtime = mtime;
      logger.debug({ mtime }, 'index.html SRI cache refreshed');
    }
  } catch (err) {
    logger.error({ err: err.message }, 'Failed to read index.html for SRI cache');
    _sriHtml = null;
  }
  return _sriHtml;
}

// ── First-run setup API ───────────────────────────────────────────────────────

const SETUP_FILE = path.join(__dirname, '.setup_complete');

// Hard server-side lockout once first-run setup is complete. The sentinel file is
// written by /api/setup-complete; subsequent re-entry attempts are refused.
// The client redirect in Setup.tsx is cosmetic — this is the actual enforcement.
function refuseIfSetupDone(_req, res, next) {
  if (existsSync(SETUP_FILE)) {
    return res.status(410).json({ error: 'setup already completed' });
  }
  next();
}

// Vend the setup token only to localhost callers while setup is pending.
// Host and Origin headers are also validated to block DNS-rebinding attacks.
app.get('/api/setup-token', refuseIfSetupDone, requireLocalOrigin, (req, res) => {
  res.json({ token: SETUP_TOKEN });
});

// Require setup token or localhost to prevent external enumeration of setup state.
app.get('/api/setup-status', (req, res) => {
  const hasToken = req.headers['x-setup-token'] === SETUP_TOKEN;
  if (!hasToken && !isLocalhost(req)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  res.json({ completed: existsSync(SETUP_FILE) });
});

// Atomic write + O_EXCL so a racing double-POST cannot create the sentinel twice.
app.post('/api/setup-complete', refuseIfSetupDone, requireSetupToken, (_req, res) => {
  try {
    writeFileSync(SETUP_FILE, new Date().toISOString(), { flag: 'wx', mode: 0o400 });
    // Invalidate the setup token immediately to prevent reuse.
    SETUP_TOKEN = null;
    res.json({ success: true });
  } catch (err) {
    if (err.code === 'EEXIST') {
      return res.status(410).json({ success: false, error: 'setup already completed' });
    }
    res.status(500).json({ success: false, error: err.message });
  }
});

// Only accessible during setup phase.
app.get('/api/system-info', refuseIfSetupDone, requireSetupToken, requireLocalOrigin, (_req, res) => {
  const script = path.join(__dirname, 'scripts', 'detect-system.sh');
  // execFile passes the script path as an argument to bash — not interpolated into
  // a shell string — eliminating any injection surface from the server-controlled path.
  execFile('bash', [script], { timeout: 10_000 }, (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message });
    try {
      res.json(JSON.parse(stdout.trim()));
    } catch {
      res.status(500).json({ error: 'parse_failed' });
    }
  });
});

// Pro token validated to alphanumeric-only and passed as execFile argument (not a shell
// string) to eliminate injection surface. Setup token acts as CSRF protection.
app.post('/api/ubuntu-pro/attach', requireSetupToken, requireLocalOrigin, async (req, res) => {
  if (!await checkSetupExecRate(clientIp(req), res)) {
    return res.status(429).json({ success: false, error: 'too_many_requests' });
  }
  const { token } = req.body ?? {};
  if (!token || typeof token !== 'string' || !/^[A-Za-z0-9]+$/.test(token)) {
    return res.status(400).json({ success: false, error: 'Invalid token format. Token must be alphanumeric.' });
  }
  execFile('sudo', ['-n', 'pro', 'attach', token], { timeout: 60_000 }, (err, stdout, stderr) => {
    const output = (stdout + stderr).trim();
    if (err) {
      return res.json({ success: false, output });
    }
    res.json({ success: true, output });
  });
});

// Requires Ubuntu Pro to be attached first. A reboot is needed after enabling FIPS.
app.post('/api/ubuntu-pro/enable-fips', requireSetupToken, requireLocalOrigin, async (req, res) => {
  if (!await checkSetupExecRate(clientIp(req), res)) {
    return res.status(429).json({ success: false, error: 'too_many_requests' });
  }
  execFile('sudo', ['-n', 'pro', 'enable', 'fips', '--assume-yes'], { timeout: 300_000 }, (err, stdout, stderr) => {
    const output = (stdout + stderr).trim();
    // exit code 0 = success; some pro versions exit 1 but still succeed — check output
    const rebootRequired = output.toLowerCase().includes('reboot');
    if (err && !output.toLowerCase().includes('fips is already enabled')) {
      return res.json({ success: false, output, reboot_required: false });
    }
    res.json({ success: true, output, reboot_required: rebootRequired });
  });
});

// ── Prometheus metrics endpoint ───────────────────────────────────────────────
// Loopback-only — never exposed to the internet.
app.get('/metrics', async (req, res) => {
  if (!isLocalhost(req)) { return res.status(403).end(); }
  res.set('Content-Type', promRegister.contentType);
  res.end(await promRegister.metrics());
});

// ── Health probe ──────────────────────────────────────────────────────────────
// Returns 200 with diagnostics (localhost only) or 503 when the daemon is unreachable.
// Non-local callers receive only a minimal { status: 'ok' } — no version/PID fingerprint.

const SERVER_START_TIME = Date.now();

app.get('/health', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  if (!isLocalhost(req)) {
    return res.status(200).json({ status: 'ok' });
  }
  // Probe the daemon over gRPC (Ping). The daemon no longer binds a Unix
  // socket — it speaks gRPC on 127.0.0.1:50051 (see grpcClient below).
  let responded = false;
  const probeStart = Date.now();
  const deadline = new Date(Date.now() + 3000);

  grpcClient.Ping({}, daemonMetadata(), { deadline }, (err) => {
    if (responded) return;
    responded = true;
    const mem = process.memoryUsage();
    if (err) {
      return res.status(503).json({
        status:       'unhealthy',
        reason:       err.details || err.message || 'daemon_unreachable',
        pid:          process.pid,
        uptime_secs:  Math.floor(process.uptime()),
        node_version: process.version,
        mem_rss_mib:  +(mem.rss / 1048576).toFixed(1),
        daemon_ok:    false,
      });
    }
    res.status(200).json({
      status:            'ok',
      pid:               process.pid,
      uptime_secs:       Math.floor(process.uptime()),
      node_version:      process.version,
      mem_rss_mib:       +(mem.rss / 1048576).toFixed(1),
      mem_heap_mib:      +(mem.heapUsed / 1048576).toFixed(1),
      daemon_ok:         true,
      daemon_latency_ms: Date.now() - probeStart,
      server_start_iso:  new Date(SERVER_START_TIME).toISOString(),
    });
  });
});

// ── DNS record check — public utility (DNS is public info, no auth needed) ────
// Fans out ~35 DNS lookups per call (MX/TXT/DMARC/BIMI + DKIM selector probes)
// against a caller-supplied domain. Rate-limited to prevent DNS amplification.
app.get('/api/system/dns-check', async (req, res) => {
  if (!await checkDnsRate(clientIp(req), res)) {
    return res.status(429).json({ error: 'too_many_requests' });
  }
  const { domain } = req.query;
  if (!domain || typeof domain !== 'string' || !/^[a-zA-Z0-9._-]{1,253}$/.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain' });
  }
  const cleanDomain = domain.toLowerCase().trim();
  const dkimSelectors = [
    'mail', 'default', 'google', 'selector1', 'selector2',
    // Zoho
    'zoho', 'zmail', 'zm1', 'zm2', '1024', '2048',
    // Other providers
    'k1', 'k2', 'k3', 'dkim', 'smtp', 'email', 's1', 's2',
    'protonmail', 'protonmail2', 'protonmail3',
    'amazonses', 'postmark', 'mandrill', 'cm', 'mimecast',
    'dkim2', 'sig1', 'everlytickey1', 'everlytickey2',
  ];

  const [mxR, txtR, dmarcR, dkimR, bimiR] = await Promise.allSettled([
    dnsPromises.resolveMx(cleanDomain),
    dnsPromises.resolveTxt(cleanDomain),
    dnsPromises.resolveTxt(`_dmarc.${cleanDomain}`),
    Promise.allSettled(
      dkimSelectors.map(sel => dnsPromises.resolveTxt(`${sel}._domainkey.${cleanDomain}`))
    ),
    dnsPromises.resolveTxt(`default._bimi.${cleanDomain}`),
  ]);

  const mx = mxR.status === 'fulfilled'
    ? mxR.value.sort((a, b) => a.priority - b.priority).map(r => r.exchange)
    : [];

  const spf = txtR.status === 'fulfilled'
    && txtR.value.some(r => r.join('').toLowerCase().startsWith('v=spf1'));

  const dmarc = dmarcR.status === 'fulfilled'
    && dmarcR.value.some(r => r.join('').toLowerCase().startsWith('v=dmarc1'));

  let dkim = false;
  if (dkimR.status === 'fulfilled') {
    dkim = dkimR.value.some(
      r => r.status === 'fulfilled' && r.value.some(txt => {
        const joined = txt.join('');
        return joined.includes('v=DKIM1') || (joined.includes('p=') && joined.includes('k='));
      })
    );
  }

  let bimi = false;
  let bimiTxt = '';
  if (bimiR.status === 'fulfilled') {
    bimiTxt = bimiR.value.flat().join('');
    bimi = bimiTxt.toLowerCase().startsWith('v=bimi1');
  }

  // VMC: referenced in BIMI record's a= parameter (points to a .pem certificate)
  const vmc = bimi && /a=[^\s;]+\.pem/i.test(bimiTxt);

  res.json({ domain: cleanDomain, mx, spf, dmarc, dkim, bimi, vmc });
});

mountAuthAndVault(app);

// ── SPA catch-all ────────────────────────────────────────────────────────────
app.get('*path', (req, res) => {
  const indexHtml = getSriHtml();
  if (!indexHtml) {
    return res.status(503).send('Application not built. Run: npm run build');
  }
  const nonce = res.locals.cspNonce;
  const html = indexHtml
    .replace(/<script /g, `<script nonce="${nonce}" `)
    .replace(/<link rel="modulepreload"/g, `<link nonce="${nonce}" rel="modulepreload"`);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  // index.html content changes with every build (new asset hashes); never cache it.
  res.setHeader('Cache-Control', 'no-store');
  res.send(html);
});

// ── Vault Daemon gRPC Proxy ───────────────────────────────────────────────────

const PROTO_PATH = path.join(__dirname, '../proto/vault.proto');
const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});
const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
const vaultProto = protoDescriptor.vault;

const grpcClient = new vaultProto.VaultService(
  DAEMON_GRPC_ADDR,
  grpc.credentials.createInsecure()
);

// Peer-auth token shared with the daemon (replaces SO_PEERCRED). Resolved from
// DAEMON_GRPC_TOKEN, else the 0600 token file the daemon writes on first boot.
const DAEMON_GRPC_TOKEN_FILE = process.env.DAEMON_GRPC_TOKEN_FILE
  || path.join(__dirname, '../daemon_data/grpc.token');
let _cachedDaemonToken = null;
function daemonToken() {
  if (_cachedDaemonToken) return _cachedDaemonToken;
  const fromEnv = (process.env.DAEMON_GRPC_TOKEN || '').trim();
  if (fromEnv) { _cachedDaemonToken = fromEnv; return fromEnv; }
  try {
    const t = readFileSync(DAEMON_GRPC_TOKEN_FILE, 'utf8').trim();
    if (t) { _cachedDaemonToken = t; return t; }
  } catch { /* token file not present yet */ }
  return '';
}
function daemonMetadata() {
  const md = new grpc.Metadata();
  const t = daemonToken();
  if (t) md.set('x-daemon-token', t);
  return md;
}

// Defense-in-depth for the gRPC bridge: a standard CSRF cookie check is not
// applicable here because daemon-mode auth carries its session token in the
// request body rather than a cookie. Instead, (a) per-IP rate limiting and
// (b) same-origin Origin/Referer enforcement are used to block cross-site
// Unlock attempts from third-party pages.
const RPC_LOCAL_ORIGIN_RE = /^https?:\/\/(localhost|127\.0\.0\.1|::1|\[::1\])(:\d+)?$/i;

app.post('/api/rpc', async (req, res) => {
  if (!await checkRpcRate(clientIp(req), res)) {
    return res.status(429).json({ error: 'too_many_requests' });
  }

  const host = req.headers['host'];
  const sameOriginRe = host
    ? new RegExp(`^https?://${host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i')
    : null;
  const isAllowedOrigin = (originUrl) => {
    if (sameOriginRe && sameOriginRe.test(originUrl)) return true;
    return RPC_LOCAL_ORIGIN_RE.test(originUrl);
  };

  const origin = req.headers['origin'];
  const referer = req.headers['referer'];
  if (origin) {
    if (!isAllowedOrigin(origin)) {
      return res.status(403).json({ error: 'forbidden_origin' });
    }
  } else if (referer) {
    try {
      if (!isAllowedOrigin(new URL(referer).origin)) {
        return res.status(403).json({ error: 'forbidden_origin' });
      }
    } catch {
      return res.status(403).json({ error: 'forbidden_referer' });
    }
  } else {
    // Fail closed: a same-origin browser fetch() always sends Origin, and
    // same-origin navigations always send Referer. A request with neither is
    // not a legitimate browser call and is rejected.
    return res.status(403).json({ error: 'forbidden_no_origin' });
  }

  const { method, payload } = req.body;
  if (!method) return res.status(400).json({ error: 'Method required' });

  if (typeof grpcClient[method] !== 'function') {
    return res.status(404).json({ error: `Method ${method} not found` });
  }

  const callPayload = payload || {};

  const convertArraysToBuffers = (obj) => {
    if (Array.isArray(obj)) {
      if (obj.length > 0 && typeof obj[0] === 'number') {
        return Buffer.from(obj);
      }
      return obj.map(convertArraysToBuffers);
    } else if (obj !== null && typeof obj === 'object') {
      const newObj = {};
      for (const key in obj) {
        newObj[key] = convertArraysToBuffers(obj[key]);
      }
      return newObj;
    }
    return obj;
  };

  const grpcPayload = convertArraysToBuffers(callPayload);

  grpcClient[method](grpcPayload, daemonMetadata(), (error, response) => {
    if (error) {
      return res.json({ status: 'Error', data: { code: error.code || error.message, message: error.details || error.message } });
    }
    const convertBuffersToArrays = (obj) => {
      if (Buffer.isBuffer(obj)) {
        return Array.from(obj);
      } else if (Array.isArray(obj)) {
        return obj.map(convertBuffersToArrays);
      } else if (obj !== null && typeof obj === 'object') {
        const newObj = {};
        for (const key in obj) {
          newObj[key] = convertBuffersToArrays(obj[key]);
        }
        return newObj;
      }
      return obj;
    };

    res.json({ status: 'Ok', data: convertBuffersToArrays(response) });
  });
});

const mainServer = tlsOptions
  ? createHttpsServer(tlsOptions, app)
  : createHttpServer(app);

const listenPort = tlsOptions ? SSL_PORT : PORT;


// ── Start ─────────────────────────────────────────────────────────────────────

// SSL=force: spin up a plain-HTTP redirect server on PORT to catch direct HTTP
// connections that bypass Nginx, in addition to the HTTPS mainServer.
if (SSL_MODE === 'force' && tlsOptions) {
  const httpRedirect = express();
  httpRedirect.use((req, res) => {
    const host = (req.headers.host || 'localhost').replace(/:\d+$/, '');
    const target = `https://${host}${SSL_PORT !== 443 ? `:${SSL_PORT}` : ''}${req.url}`;
    res.redirect(301, target);
  });
  const redirectServer = createHttpServer(httpRedirect);
  redirectServer.listen(PORT, BIND_HOST, () => {
    logger.info({ bindHost: BIND_HOST, port: PORT, httpsPort: SSL_PORT }, 'HTTP→HTTPS redirect server listening');
  });
  redirectServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      logger.warn({ port: PORT, err: err.message }, 'Could not bind HTTP redirect server: port in use');
    }
  });
  // Store ref so graceful shutdown can drain this server too.
  app.locals._redirectServer = redirectServer;
}

mainServer.listen(listenPort, BIND_HOST, () => {
  const scheme = tlsOptions ? 'https' : 'http';
  logger.info({ scheme, host: BIND_HOST, port: listenPort, sslMode: SSL_MODE || 'off', env: process.env.NODE_ENV },
    'Enterprise Vault Server listening');
  // Signal PM2 that the server is ready (requires wait_ready: true in ecosystem.config.cjs).
  if (process.send) process.send('ready');
});

// ── Defunct WebSocket Handler ────────────────────────────────────────────────
// The project has migrated from WebSocket/msgpack to a gRPC-over-HTTP bridge
// at /api/rpc. We catch any stale /ws upgrade requests here and return 410 Gone.
mainServer.on('upgrade', (req, socket) => {
  if (req.url === '/ws') {
    logger.warn({ remoteAddress: req.socket.remoteAddress }, 'Defunct /ws upgrade rejected with 410 Gone');
    socket.write('HTTP/1.1 410 Gone\r\nConnection: close\r\n\r\n');
    socket.destroy();
  }
});

mainServer.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    logger.fatal({ port: listenPort, err: error.message }, 'Port already in use — change PORT/SSL_PORT in .env');
    process.exit(1);
  } else {
    logger.fatal({ err: error.message, stack: error.stack }, 'Unexpected server error');
    process.exit(1);
  }
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
// Stop accepting new connections and drain in-flight HTTP requests before
// exiting. PM2's kill_timeout must exceed DRAIN_TIMEOUT_MS.
// Override via DRAIN_TIMEOUT_MS env var (milliseconds).
const DRAIN_TIMEOUT_MS = parseInt(process.env.DRAIN_TIMEOUT_MS || '25000', 10);

function gracefulShutdown(signal) {
  logger.info({ signal, drainTimeoutMs: DRAIN_TIMEOUT_MS }, 'Signal received — stopping listener and draining');

  let closed = 0;
  const numServers = app.locals._redirectServer ? 2 : 1;
  function onClosed(err) {
    if (err) logger.error({ err: err.message }, 'Error while closing server');
    if (++closed >= numServers) {
      logger.info('All servers closed — exiting cleanly');
      process.exit(err ? 1 : 0);
    }
  }

  // Close the HTTPS/HTTP main server.
  mainServer.close(onClosed);

  // Also close the HTTP→HTTPS redirect server if it is running (Fix #9).
  if (app.locals._redirectServer) {
    app.locals._redirectServer.close(onClosed);
  }

  // Hard-exit fallback to prevent hung deploys.
  setTimeout(() => {
    logger.error({ drainTimeoutMs: DRAIN_TIMEOUT_MS }, 'Drain timeout exceeded — forcing exit');
    process.exit(1);
  }, DRAIN_TIMEOUT_MS).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));
