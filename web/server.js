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
import { WebSocketServer } from 'ws';
import net from 'net';
import { initAuth, mountAuthAndVault, getServerPublicIp } from './auth.js';
import { promises as dnsPromises } from 'dns';

dotenv.config();

// #8-FIX: fail closed if NODE_ENV is not set — defaults to 'development' silently
// allow sensitive logging to fire in production-like launchers (CWE-209).
if (!process.env.NODE_ENV) {
  throw new Error('NODE_ENV must be set explicitly (set to "production" in production launchers)');
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || '1234', 10);
const BIND_HOST = process.env.BIND_HOST || '127.0.0.1';
const DAEMON_SOCKET = process.env.VAULT_SOCKET || '/run/vault-daemon/vault.sock';
// #24-FIX: reject /tmp-based socket paths unless explicitly overridden for testing.
if (DAEMON_SOCKET.startsWith('/tmp/') && process.env.VAULT_ALLOW_INSECURE_SOCKET !== '1') {
  throw new Error(`VAULT_SOCKET "${DAEMON_SOCKET}" uses /tmp — set VAULT_ALLOW_INSECURE_SOCKET=1 to override (not for production use)`);
}

// Guard: in production, nginx proxies to port 1234 — a mismatch causes 502.
if (process.env.NODE_ENV === 'production' && PORT !== 1234) {
  console.warn(`[server] WARNING: PORT=${PORT} but nginx upstream expects 1234. This will cause 502 Bad Gateway.`);
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
    console.log('[SSL] Dual-cert ECDSA+RSA loaded from', SSL_DIR);
  } else if (hasEcdsa) {
    tlsOptions = { cert: readFileSync(ecdsaCert), key: readFileSync(ecdsaKey), minVersion: 'TLSv1.3' };
    console.log('[SSL] ECDSA cert loaded from', SSL_DIR);
  } else if (hasRsa) {
    tlsOptions = { cert: readFileSync(rsaCert), key: readFileSync(rsaKey), minVersion: 'TLSv1.3' };
    console.log('[SSL] RSA cert loaded from', SSL_DIR);
  } else if (hasFlat) {
    tlsOptions = { cert: readFileSync(flatCert), key: readFileSync(flatKey), minVersion: 'TLSv1.2' };
    console.log('[SSL] Single cert loaded from', SSL_DIR);
  } else {
    console.warn(`[SSL] SSL=${SSL_MODE} but no certificates found in ${SSL_DIR}.`);
    console.warn(`[SSL] Place your cert at: ${flatCert}`);
    console.warn(`[SSL] Place your key  at: ${flatKey}`);
    console.warn('[SSL] Or run:  npm run ssl:generate  to create a self-signed cert.');
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

export const wsConnections = new Gauge({
  name: 'pwdnow_ws_connections_active',
  help: 'Number of active WebSocket connections',
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

initAuth({ dataDir: DATA_DIR });

// Skip compression on /api/ routes to prevent BREACH/HEIST side-channel attacks
// on authenticated JSON responses. Static assets and SPA HTML are safe to compress.
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  return compression()(req, res, next);
});
app.use(cookieParser());

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${new Date().toISOString()} ${req.method} ${req.url} ${res.statusCode} ${duration}ms`);
  });
  next();
});


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
        // 'self' already covers same-origin WS/WSS; no wildcard ws: needed.
        connectSrc:     ["'self'", "ws:", "wss:", "https://api.pwnedpasswords.com"],
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

// Cap JSON body size at 512 KB. Vault import uploads (which can be larger) must
// use a dedicated chunked endpoint.
app.use(express.json({ limit: '512kb' }));

app.use((_req, res, next) => {
  res.setHeader('X-Request-ID', randomBytes(8).toString('hex'));
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
      console.log(`[Server] index.html updated (mtime: ${mtime}), refreshed SRI cache.`);
    }
  } catch (err) {
    console.error('[Server] Failed to read index.html for SRI cache:', err.message);
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
// #10-FIX: also enforce that Origin/Host both resolve to localhost to block DNS-rebinding.
app.get('/api/setup-token', refuseIfSetupDone, (req, res) => {
  if (!isLocalhost(req)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  // DNS-rebinding guard: if Origin or Referer is present, it must be a localhost origin.
  const origin = req.headers['origin'];
  const referer = req.headers['referer'];
  const localOriginRe = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;
  if (origin && !localOriginRe.test(origin)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  if (referer && !localOriginRe.test(new URL(referer).origin)) {
    return res.status(403).json({ error: 'forbidden' });
  }
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
app.get('/api/system-info', refuseIfSetupDone, requireSetupToken, (_req, res) => {
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
app.post('/api/ubuntu-pro/attach', requireSetupToken, (req, res) => {
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
app.post('/api/ubuntu-pro/enable-fips', requireSetupToken, (_req, res) => {
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
  const socketAddr = req.socket.remoteAddress || '';
  const isLocal = socketAddr === '127.0.0.1' || socketAddr === '::1' || socketAddr === '::ffff:127.0.0.1';
  if (!isLocal) { return res.status(403).end(); }
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
  const socket = net.createConnection(DAEMON_SOCKET);
  let responded = false;
  const probeStart = Date.now();

  const fail = (reason) => {
    if (!responded) {
      responded = true;
      socket.destroy();
      const mem = process.memoryUsage();
      res.status(503).json({
        status:      'unhealthy',
        reason,
        pid:         process.pid,
        uptime_secs: Math.floor(process.uptime()),
        node_version: process.version,
        mem_rss_mib:  +(mem.rss / 1048576).toFixed(1),
        daemon_ok:   false,
      });
    }
  };

  socket.setTimeout(3000);
  socket.on('connect', () => {
    if (!responded) {
      responded = true;
      const latency_ms = Date.now() - probeStart;
      socket.destroy();
      const mem = process.memoryUsage();
      res.status(200).json({
        status:         'ok',
        pid:            process.pid,
        uptime_secs:    Math.floor(process.uptime()),
        node_version:   process.version,
        mem_rss_mib:    +(mem.rss / 1048576).toFixed(1),
        mem_heap_mib:   +(mem.heapUsed / 1048576).toFixed(1),
        daemon_ok:      true,
        daemon_latency_ms: latency_ms,
        server_start_iso: new Date(SERVER_START_TIME).toISOString(),
      });
    }
  });
  socket.on('timeout', () => fail('daemon_timeout'));
  socket.on('error',   (err) => fail(err.message));
});

// ── DNS record check — public utility (DNS is public info, no auth needed) ────
app.get('/api/system/dns-check', async (req, res) => {
  const { domain } = req.query;
  if (!domain || typeof domain !== 'string' || !/^[a-zA-Z0-9._-]{1,253}$/.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain' });
  }
  const cleanDomain = domain.toLowerCase().trim();
  const dkimSelectors = ['mail', 'default', 'google', 'selector1', 'selector2'];

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
      r => r.status === 'fulfilled' && r.value.some(txt => txt.join('').includes('v=DKIM1'))
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

// ─────────────────────────────────────────────────────────────────────────────

app.get('*', (req, res) => {
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

// ── Vault Daemon WebSocket Proxy ──────────────────────────────────────────────
// Each browser WS connection gets its own Unix socket connection to the daemon.
// Browser binary messages (raw msgpack) are prefixed with a 4-byte big-endian
// length and forwarded; daemon length-prefixed frames are stripped and forwarded back.

const mainServer = tlsOptions
  ? createHttpsServer(tlsOptions, app)
  : createHttpServer(app);

// Cap WebSocket frame size at 4 MiB — matches daemon's MAX_FRAME_SIZE.
const wss = new WebSocketServer({ server: mainServer, path: '/ws', maxPayload: 4 * 1024 * 1024 });

// Allowed WebSocket origins — populated once at startup, checked on each connection.
const listenPort = tlsOptions ? SSL_PORT : PORT;
const ALLOWED_WS_ORIGINS = new Set([
  `http://localhost:${PORT}`,
  `https://localhost:${PORT}`,
  `http://127.0.0.1:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  ...(tlsOptions ? [
    `https://localhost:${SSL_PORT}`,
    `https://127.0.0.1:${SSL_PORT}`,
  ] : []),
  // Operator-configured production domain
  ...(process.env.VAULT_ORIGIN ? [process.env.VAULT_ORIGIN] : []),
]);

// Per-IP reconnect throttle — max 30 connections per minute per IP.
const wsConnectCounts = new Map(); // ip -> { count, resetAt }
const WS_CONNECT_WINDOW_MS = 60_000;
const WS_CONNECT_LIMIT = 30;

function isWsRateLimited(ip) {
  // M-9 fix: port the immutable-update pattern from auth.js:106-118.
  // The previous code did `entry.count += 1` AFTER the get/set, which under
  // burst load could spike the counter above the cap briefly because a
  // concurrent message handler reading the entry would see the old count
  // while we are about to increment it. Constructing a fresh entry object
  // and overwriting via .set is a single atomic step (Map.set is sync).
  const now = Date.now();
  const e = wsConnectCounts.get(ip) ?? { count: 0, resetAt: now + WS_CONNECT_WINDOW_MS };
  const reset = now > e.resetAt;
  const next = {
    count: reset ? 1 : e.count + 1,
    resetAt: reset ? now + WS_CONNECT_WINDOW_MS : e.resetAt,
  };
  wsConnectCounts.set(ip, next);
  return next.count > WS_CONNECT_LIMIT;
}

// Per-tab nonce rate limiter — max 200 IPC commands per minute per tab.
const wsNonceCounts = new Map(); // nonce -> { count, resetAt }
const WS_NONCE_WINDOW_MS = 60_000;
const WS_NONCE_LIMIT = 200;

let activeWsCount = 0;
const MAX_GLOBAL_WS_CONNECTIONS = 200;

wss.on('connection', (ws, req) => {
  const clientIp = req.headers['x-real-ip'] || req.socket.remoteAddress || '';
  if (isWsRateLimited(clientIp)) {
    ws.close(1013, 'too many connections from this IP');
    return;
  }

  if (activeWsCount >= MAX_GLOBAL_WS_CONNECTIONS) {
    ws.close(1013, 'server busy (max connections reached)');
    return;
  }
  activeWsCount++;

  // Drop stalling connections within 10s to prevent Slowloris-style exhaustion.
  let hasReceivedData = false;
  const handshakeTimeout = setTimeout(() => {
    if (!hasReceivedData) {
      ws.close(1008, 'handshake timeout');
    }
  }, 10_000);

  ws.on('close', () => {
    activeWsCount--;
    clearTimeout(handshakeTimeout);
  });

  // #2-FIX: Validate Origin against the strict allow-list only — drop isSameHost
  // fallback that DNS-rebinding can satisfy with attacker-controlled Host header.
  const origin = req.headers['origin'];
  if (!origin || !ALLOWED_WS_ORIGINS.has(origin)) {
    ws.close(1008, 'origin not allowed');
    return;
  }

  // #2-FIX: Sec-Tab-Nonce is mandatory; both the cookie and query param must be
  // present and equal. Accepting a query-only nonce when the cookie is absent
  // allows cross-site WS from pages that never set the cookie.
  const url = new URL(req.url, `http://${req.headers.host}`);
  const queryNonce = url.searchParams.get('nonce');
  let cookieNonce = null;
  const cookies = (req.headers.cookie || '').split(';');
  for (const c of cookies) {
    if (c.trim().startsWith('Sec-Tab-Nonce=')) {
      cookieNonce = c.split('=')[1].trim();
    }
  }

  if (!cookieNonce || cookieNonce !== queryNonce) {
    ws.close(1008, 'tab nonce mismatch');
    return;
  }

  const daemon = net.createConnection(DAEMON_SOCKET);
  let readBuf = Buffer.alloc(0);

  daemon.on('connect', () => {});

  // Browser → Daemon
  ws.on('message', (data) => {
    hasReceivedData = true;
    // M-9 fix: immutable update (matches auth.js:106-118 / isWsRateLimited).
    // Drive-by fix: the previous code referenced an undefined `nonce` symbol
    // (typo for `cookieNonce`) so the rate-limiter was a no-op. Fixed here.
    const now = Date.now();
    const prior = wsNonceCounts.get(cookieNonce) ?? { count: 0, resetAt: now + WS_NONCE_WINDOW_MS };
    const reset = now > prior.resetAt;
    const updated = {
      count: reset ? 1 : prior.count + 1,
      resetAt: reset ? now + WS_NONCE_WINDOW_MS : prior.resetAt,
    };
    wsNonceCounts.set(cookieNonce, updated);
    if (updated.count > WS_NONCE_LIMIT) {
      ws.close(1008, 'rate limit exceeded for this tab');
      return;
    }

    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(buf.length, 0);
    daemon.write(Buffer.concat([lenBuf, buf]));
  });

  // Daemon → Browser
  daemon.on('data', (chunk) => {
    readBuf = Buffer.concat([readBuf, chunk]);
    while (readBuf.length >= 4) {
      const frameLen = readBuf.readUInt32BE(0);
      if (readBuf.length < 4 + frameLen) break; // incomplete frame — wait for more data
      const frame = readBuf.slice(4, 4 + frameLen);
      if (ws.readyState === ws.OPEN) ws.send(frame);
      readBuf = readBuf.slice(4 + frameLen);
    }
  });

  daemon.on('error', (err) => {
    if (ws.readyState === ws.OPEN) {
      ws.close(1011, `daemon unavailable: ${err.message}`);
    }
  });

  daemon.on('close', () => {
    if (ws.readyState === ws.OPEN) ws.close(1001, 'daemon disconnected');
  });

  ws.on('close', () => { daemon.destroy(); });
  ws.on('error', (e) => { daemon.destroy(); });
});


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
    console.log(`[SSL] HTTP redirect server on http://${BIND_HOST}:${PORT} → HTTPS:${SSL_PORT}`);
  });
  redirectServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.warn(`[SSL] Could not bind HTTP redirect to port ${PORT}: already in use`);
    }
  });
}

mainServer.listen(listenPort, BIND_HOST, () => {
  const scheme = tlsOptions ? 'https' : 'http';
  console.log(`Enterprise Vault Server running on ${scheme}://${BIND_HOST}:${listenPort}`);
  if (tlsOptions) console.log(`[SSL] Mode: ${SSL_MODE} | Certs: ${SSL_DIR}`);
  console.log(`Vault daemon status: connecting to backend...`);
  // Signal PM2 that the server is ready (requires wait_ready: true in ecosystem.config.cjs).
  if (process.send) process.send('ready');
});

mainServer.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`\n CRITICAL ERROR: Port ${listenPort} is already in use!`);
    console.error(`Please stop the process using port ${listenPort} or change the PORT/SSL_PORT in your .env file.\n`);
    process.exit(1);
  } else {
    console.error('An unexpected server error occurred:', error);
    process.exit(1);
  }
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
// Stop accepting new connections, drain in-flight WS frames and HTTP requests,
// then exit cleanly. PM2 kill_timeout must be > DRAIN_TIMEOUT_MS.
const DRAIN_TIMEOUT_MS = 25_000;

function gracefulShutdown(signal) {
  console.log(`[server] ${signal} received — stopping listener, draining (max ${DRAIN_TIMEOUT_MS / 1000}s)...`);

  // Stop the WebSocket server from accepting new upgrades.
  wss.close(() => { console.log('[server] WebSocket server closed'); });

  // Stop accepting new HTTP(S) connections; drain existing keep-alive connections.
  mainServer.close((err) => {
    if (err) console.error('[server] mainServer.close error:', err);
    else console.log('[server] Server closed — exiting cleanly');
    process.exit(err ? 1 : 0);
  });

  // Hard-exit fallback to prevent hung deploys.
  setTimeout(() => {
    console.error('[server] Drain timeout exceeded — forcing exit');
    process.exit(1);
  }, DRAIN_TIMEOUT_MS).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));
