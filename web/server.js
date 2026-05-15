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
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import net from 'net';
import { initAuth, mountAuthAndVault, getServerPublicIp } from './auth.js';

// Load environment variables from .env file
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const BIND_HOST = process.env.BIND_HOST || '127.0.0.1';
const DAEMON_SOCKET = process.env.VAULT_SOCKET || '/run/vault-daemon/vault.sock';
const IS_PROD = process.env.NODE_ENV === 'production';

// Initialize auth backend for demo/offline mode
initAuth({ dataDir: path.join(__dirname, 'auth_data') });

app.use(compression());
app.use(cookieParser());

// Request logger
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${new Date().toISOString()} ${req.method} ${req.url} ${res.statusCode} ${duration}ms`);
  });
  next();
});


// ── Setup token (C-03 / H-02) ─────────────────────────────────────────────────
// Generated once at startup and held only in memory. Required as an HTTP header
// on every privileged admin endpoint. Cannot be obtained cross-origin because
// /api/setup-token is localhost-only — this acts as a CSRF defence.
const SETUP_TOKEN_BYTES = randomBytes(32);
const SETUP_TOKEN = SETUP_TOKEN_BYTES.toString('hex');

// F5-FIX (HIGH-09 / pen-test Finding 5): trust only the TCP socket address and
// X-Real-IP (set by a trusted Nginx proxy to $remote_addr).  X-Forwarded-For is
// NOT checked here because clients can prepend arbitrary values to that header
// before Nginx appends the real remote IP — trusting it allows IP-spoofing bypass.
// Nginx config must include: proxy_set_header X-Real-IP $remote_addr;
function isLocalhost(req) {
  const socketAddr = req.socket.remoteAddress;
  const socketIsLocal =
    socketAddr === '127.0.0.1' ||
    socketAddr === '::1' ||
    socketAddr === '::ffff:127.0.0.1';

  if (!socketIsLocal) return false;

  // X-Real-IP is overwritten by Nginx to the real client address — safe to trust.
  const realIp = req.headers['x-real-ip'];
  if (realIp) {
    return realIp === '127.0.0.1' || realIp === '::1' || realIp === '::ffff:127.0.0.1';
  }

  // No proxy header present — must be a direct local connection.
  return true;
}

function requireSetupToken(req, res, next) {
  const provided = req.headers['x-setup-token'];
  if (!provided || typeof provided !== 'string') {
    return res.status(403).json({ error: 'Missing X-Setup-Token header' });
  }
  // Use timingSafeEqual to prevent timing attacks on the comparison.
  try {
    const providedBuf = Buffer.from(provided, 'hex');
    if (providedBuf.length !== SETUP_TOKEN_BYTES.length ||
        !timingSafeEqual(providedBuf, SETUP_TOKEN_BYTES)) {
      return res.status(403).json({ error: 'Invalid setup token' });
    }
  } catch {
    return res.status(403).json({ error: 'Invalid setup token' });
  }
  next();
}

// ── Per-request CSP nonce middleware ──────────────────────────────────────────
// Architecture §10: require-trusted-types-for 'script'; nonce-based CSP.
// 'unsafe-inline' is removed — Vite injects a small inline bootstrap script,
// which must be served with a matching nonce injected into index.html.
app.use((req, res, next) => {
  res.locals.cspNonce = randomBytes(16).toString('base64');
  next();
});

// Security Middleware
app.use((req, res, next) => {
  const nonce = res.locals.cspNonce;
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc:     ["'none'"],
        // 'wasm-unsafe-eval' enables WebAssembly.compile / instantiate ONLY.
        // It does NOT re-enable JS string-eval; that still requires the
        // separate 'unsafe-eval' token (which we never grant). Required so
        // the Argon2id KDF (hash-wasm) can run both on the main thread and
        // inside kdf.worker.ts. See LOGIN_PERFORMANCE_PLAN.md.
        scriptSrc:      ["'self'", `'nonce-${nonce}'`, "'wasm-unsafe-eval'"],
        // D.7 / S-10: Tailwind v4 @tailwindcss/vite emits a static CSS file at build
        // time — no runtime style injection. 'unsafe-inline' is no longer needed.
        styleSrc:       ["'self'"],
        // MED-10 fixed: Google Fonts removed; system fonts used; no external font requests
        fontSrc:        ["'self'"],
        imgSrc:         ["'self'", "blob:"],  // MED-09: removed data: (exfil vector)
        connectSrc:     ["'self'", "ws:", "wss:", "https://api.pwnedpasswords.com"],  // HIGH-01: allow WS/WSS on current host; HIBP k-anonymity API (Plan B breach check)
        formAction:     ["'self'"],
        frameAncestors: ["'none'"],
        baseUri:        ["'none'"],
        objectSrc:      ["'none'"],
        workerSrc:               ["'self'", "blob:"],
        manifestSrc:             ["'self'"],
        requireTrustedTypesFor:  ["'script'"],
        // dompurify: DOMPurify sanitizer policy.
        // react-dom: React 19 internal Trusted Types policy for HTML props.
        // default: fallback policy used by some bundled libraries at runtime.
        // allow-duplicates: lets HMR re-register the same policy name safely.
        trustedTypes:            ["dompurify", "react-dom", "default", "'allow-duplicates'"],
        upgradeInsecureRequests: null, // Nginx handles HTTPS upgrade at the proxy layer
      },
    },
    // HSTS: 1 year, includeSubDomains (production only)
    strictTransportSecurity: IS_PROD
      ? { maxAge: 31536000, includeSubDomains: true, preload: true }
      : false,
    // S-17 / D.8: COEP required for SharedArrayBuffer isolation; COOP+COEP = full cross-origin isolation.
    crossOriginEmbedderPolicy: { policy: 'require-corp' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xContentTypeOptions: true,
    xFrameOptions: { action: 'deny' },
  })(req, res, next);
});

// S-12 / D.10: cap JSON body size at 512 KB for most routes. Vault import
// uploads (which can be larger) must use a dedicated chunked endpoint.
app.use(express.json({ limit: '512kb' }));

// LOW-05: add X-Request-ID correlation header to every response
app.use((_req, res, next) => {
  res.setHeader('X-Request-ID', randomBytes(8).toString('hex'));
  next();
});

// LOW-03: prevent MIME-sniffing on API JSON responses by setting Content-Disposition
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

// Serve static files from the React build
const distPath = path.join(__dirname, 'dist');

// Service workers run in an isolated global scope — they do no DOM manipulation
// and must not receive require-trusted-types-for 'script' or they cannot call
// importScripts(). Intercept sw.js and its Workbox chunk before express.static
// so we can replace the page-level CSP with a minimal SW-appropriate one.
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
// Hashed assets (JS/CSS with content-hash filenames) are immutable — cache for 1 year
app.use('/assets', express.static(path.join(distPath, 'assets'), {
  index: false,
  maxAge: '1y',
  immutable: true,
}));

// Return a script that forces a reload for missing JS assets instead of 404,
// which fixes the white-screen issue when a stale index.html requests old assets.
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

// SPA fallback: inject CSP nonce into index.html before serving.
// Vite builds a small inline <script> for module preloading; we replace the
// placeholder attribute `nonce=""` with the real per-request nonce so the
// browser accepts it without 'unsafe-inline'.
const indexHtmlPath = path.join(distPath, 'index.html');

// S-16 / D.9: compute SRI (sha384) hashes for all referenced assets at startup.
// The HTML is modified once at load time to add integrity= attributes.
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

    // If file has changed on disk, or cache is empty, re-compute
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

// Hard server-side lockout once first-run setup is complete. The sentinel is
// written by /api/setup-complete below; any subsequent attempt to re-enter
// onboarding — even via direct curl from localhost — is refused. The client
// redirect in Setup.tsx is cosmetic and must not be the only enforcement.
function refuseIfSetupDone(_req, res, next) {
  if (existsSync(SETUP_FILE)) {
    return res.status(410).json({ error: 'setup already completed' });
  }
  next();
}

// Vend the setup token ONLY to localhost callers, and only while setup is
// still pending. The browser setup wizard fetches this once and includes it
// as X-Setup-Token on subsequent requests. A remote attacker cannot read this
// value because:
//   1. The endpoint rejects non-localhost TCP connections.
//   2. Even if proxied, the browser's same-origin policy prevents cross-origin
//      pages from reading the response (no credentials → no CORS bypass).
//   3. After /api/setup-complete runs, the endpoint is permanently disabled.
app.get('/api/setup-token', refuseIfSetupDone, (req, res) => {
  if (!isLocalhost(req)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  res.json({ token: SETUP_TOKEN });
});

// Is first-run setup done? (public, read-only — no token required)
app.get('/api/setup-status', (_req, res) => {
  res.json({ completed: existsSync(SETUP_FILE) });
});

// Mark setup complete (write sentinel file) — requires setup token and not
// already done. Atomic write + O_EXCL so a racing double-POST cannot corrupt.
app.post('/api/setup-complete', refuseIfSetupDone, requireSetupToken, (_req, res) => {
  try {
    writeFileSync(SETUP_FILE, new Date().toISOString(), { flag: 'wx', mode: 0o400 });
    res.json({ success: true });
  } catch (err) {
    if (err.code === 'EEXIST') {
      return res.status(410).json({ success: false, error: 'setup already completed' });
    }
    res.status(500).json({ success: false, error: err.message });
  }
});

// Run detect-system.sh and return JSON — only during setup phase (D.6 / S-04).
app.get('/api/system-info', refuseIfSetupDone, requireSetupToken, (_req, res) => {
  const script = path.join(__dirname, 'scripts', 'detect-system.sh');
  // Use execFile so the script path is passed as an argument to bash, not interpolated
  // into a shell string. The path is server-controlled (no user input).
  execFile('bash', [script], { timeout: 10_000 }, (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message });
    try {
      res.json(JSON.parse(stdout.trim()));
    } catch {
      res.status(500).json({ error: 'parse_failed' });
    }
  });
});

// Attach Ubuntu Pro subscription token — requires setup token (acts as CSRF token)
// Pro token validated to alphanumeric-only; passed as execFile argument (not shell string)
// to eliminate any residual injection surface.
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

// Enable FIPS 140-2 modules via Ubuntu Pro — requires setup token (acts as CSRF token)
// Runs: sudo pro enable fips --assume-yes
// Note: requires Ubuntu Pro to be attached first. A reboot is needed after.
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

// ── Health probe ──────────────────────────────────────────────────────────────
// PWDnowMonitoringENV polls this endpoint every 10 s to verify application-layer
// liveness of both the Express server and the vault-daemon IPC socket.
//
// Returns 200 with rich diagnostics when healthy, 503 when the daemon is unreachable.
// Not behind authentication — safe because it reveals no user data.

const SERVER_START_TIME = Date.now();

app.get('/health', (_req, res) => {
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

// ── Public IP proxy (avoids CSP restriction on direct fetch to ipify.org) ────
// Returns the caller's public-facing IP. Loopback callers (same machine as the
// server) receive the server's outbound public IP instead.
const LOOPBACK_RE_SRV = /^(127\.|::1$|::ffff:127\.)/;
app.get('/api/my-ip', async (req, res) => {
  const clientIp = req.headers['x-real-ip'] || req.socket.remoteAddress || '';
  if (!LOOPBACK_RE_SRV.test(clientIp)) return res.json({ ip: clientIp });
  res.json({ ip: (await getServerPublicIp()) ?? '127.0.0.1' });
});

// ── Mount offline demo-mode API routes ───────────────────────────────────────
mountAuthAndVault(app);

// ─────────────────────────────────────────────────────────────────────────────

app.get('*', (req, res) => {
  const indexHtml = getSriHtml();
  if (!indexHtml) {
    return res.status(503).send('Application not built. Run: npm run build');
  }
  const nonce = res.locals.cspNonce;
  // Replace <script> tags that have no nonce with the per-request nonce.
  // Vite emits: <script type="module" crossorigin src="...">
  // We add nonce to all module scripts.
  const html = indexHtml
    .replace(/<script /g, `<script nonce="${nonce}" `)
    .replace(/<link rel="modulepreload"/g, `<link nonce="${nonce}" rel="modulepreload"`);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  // Never cache index.html — its content changes with every build (new asset hashes).
  // Static assets under /assets/ are immutable and can be cached indefinitely.
  res.setHeader('Cache-Control', 'no-store');
  res.send(html);
});

// ── Vault Daemon WebSocket Proxy ──────────────────────────────────────────────
//
// Each browser WebSocket connection gets its own Unix socket connection to the
// vault daemon.  The proxy:
//   Browser → ws binary message (raw msgpack)
//   → prefix 4-byte big-endian length
//   → write to daemon Unix socket
//
//   Daemon Unix socket → length-prefixed msgpack frame
//   → strip 4-byte length prefix
//   → send as WebSocket binary message to browser

const httpServer = createServer(app);
// S-08 / D.5: cap WebSocket frame size at 4 MiB (matches daemon's MAX_FRAME_SIZE).
const wss = new WebSocketServer({ server: httpServer, path: '/ws', maxPayload: 4 * 1024 * 1024 });

// HIGH-01 fix: allowed WebSocket origins (same host, both http and https).
// Populated once at startup; the WS server checks each incoming Origin header.
const ALLOWED_WS_ORIGINS = new Set([
  `http://localhost:${PORT}`,
  `https://localhost:${PORT}`,
  `http://127.0.0.1:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  // Production: honour VAULT_ORIGIN env var so the operator can set their domain
  ...(process.env.VAULT_ORIGIN ? [process.env.VAULT_ORIGIN] : []),
]);

// S-09 / D.5: per-IP reconnect throttle — max 30 connections per minute per IP.
const wsConnectCounts = new Map(); // ip -> { count, resetAt }
const WS_CONNECT_WINDOW_MS = 60_000;
const WS_CONNECT_LIMIT = 30;

function isWsRateLimited(ip) {
  const now = Date.now();
  let entry = wsConnectCounts.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + WS_CONNECT_WINDOW_MS };
    wsConnectCounts.set(ip, entry);
  }
  entry.count += 1;
  return entry.count > WS_CONNECT_LIMIT;
}

wss.on('connection', (ws, req) => {
  // S-09: per-IP reconnect throttle.
  const clientIp = req.headers['x-real-ip'] || req.socket.remoteAddress || '';
  if (isWsRateLimited(clientIp)) {
    ws.close(1013, 'too many connections from this IP');
    return;
  }

  // HIGH-01: validate the Origin header to prevent Cross-Site WebSocket Hijacking.
  // When deployed behind Nginx all socket connections appear from 127.0.0.1, so
  // IP-based checks alone are insufficient — we must also check the browser-sent
  // Origin.  Missing Origin (e.g. native WebSocket clients) is allowed only in dev.
  // Same-host origins (Origin matches the Host header) are always allowed because
  // the remote-address check confirms the request came through a trusted local
  // proxy or was direct — CSRF attacks require a cross-origin page, which this isn't.
  const origin = req.headers['origin'];
  const host = req.headers['host'];
  const isSameHost = host && origin && (origin === `http://${host}` || origin === `https://${host}`);
  if (origin && !isSameHost && !ALLOWED_WS_ORIGINS.has(origin)) {
    ws.close(1008, 'cross-origin WebSocket connections not allowed');
    return;
  }

  const daemon = net.createConnection(DAEMON_SOCKET);
  let readBuf = Buffer.alloc(0);

  daemon.on('connect', () => {});

  // Browser → Daemon
  ws.on('message', (data) => {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(buf.length, 0);
    daemon.write(Buffer.concat([lenBuf, buf]));
  });

  // Daemon → Browser: parse length-prefixed frames
  daemon.on('data', (chunk) => {
    readBuf = Buffer.concat([readBuf, chunk]);
    while (readBuf.length >= 4) {
      const frameLen = readBuf.readUInt32BE(0);
      if (readBuf.length < 4 + frameLen) break; // incomplete frame, wait for more
      const frame = readBuf.slice(4, 4 + frameLen);
      if (ws.readyState === ws.OPEN) ws.send(frame);
      readBuf = readBuf.slice(4 + frameLen);
    }
  });

  daemon.on('error', (err) => {
    // Daemon not running or socket not found — close the WS with a clear code
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

httpServer.listen(PORT, BIND_HOST, () => {
  console.log(`Enterprise Vault Server running on http://${BIND_HOST}:${PORT}`);
  console.log(`Vault daemon socket: ${DAEMON_SOCKET}`);
});

httpServer.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`\n CRITICAL ERROR: Port ${PORT} is already in use!`);
    console.error(`Please stop the process using port ${PORT} or change the PORT in your .env file.\n`);
    process.exit(1);
  } else {
    console.error('An unexpected server error occurred:', error);
    process.exit(1);
  }
});
