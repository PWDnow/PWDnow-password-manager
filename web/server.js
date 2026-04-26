import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomBytes, timingSafeEqual } from 'crypto';
import { exec, execFile, spawn } from 'child_process';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import net from 'net';
import { initAuth, mountAuthAndVault } from './auth.js';

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

import cookieParser from 'cookie-parser';
app.use(cookieParser());


// ── Setup token (C-03 / H-02) ─────────────────────────────────────────────────
// Generated once at startup and held only in memory. Required as an HTTP header
// on every privileged admin endpoint. Cannot be obtained cross-origin because
// /api/setup-token is localhost-only — this acts as a CSRF defence.
const SETUP_TOKEN_BYTES = randomBytes(32);
const SETUP_TOKEN = SETUP_TOKEN_BYTES.toString('hex');

// HIGH-09 fix: when behind Nginx the socket address is always 127.0.0.1 (the
// proxy), so we must also inspect X-Real-IP (set by Nginx to the client's real
// IP).  If the socket is NOT localhost we reject immediately.  If the socket IS
// localhost but X-Real-IP is set and non-local, the request came through the
// reverse proxy from a remote client — also reject.
function isLocalhost(req) {
  const socketAddr = req.socket.remoteAddress;
  const socketIsLocal =
    socketAddr === '127.0.0.1' ||
    socketAddr === '::1' ||
    socketAddr === '::ffff:127.0.0.1';

  if (!socketIsLocal) return false;

  // If Nginx set X-Real-IP, use that to check the real client address
  const realIp = req.headers['x-real-ip'];
  if (realIp) {
    return realIp === '127.0.0.1' || realIp === '::1' || realIp === '::ffff:127.0.0.1';
  }

  // Check X-Forwarded-For (first hop is the real client)
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    const clientIp = xForwardedFor.split(',')[0].trim();
    return clientIp === '127.0.0.1' || clientIp === '::1';
  }

  return true; // local socket, no proxy headers → direct local connection
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
        scriptSrc:      ["'self'", `'nonce-${nonce}'`],
        styleSrc:       ["'self'", "'unsafe-inline'"],  // Tailwind requires unsafe-inline; HIGH-08 tracked
        // MED-10 fixed: Google Fonts removed; system fonts used; no external font requests
        fontSrc:        ["'self'"],
        imgSrc:         ["'self'", "blob:"],  // MED-09: removed data: (exfil vector)
        connectSrc:     ["'self'", "ws:", "wss:"],  // HIGH-01: allow WS/WSS on current host
        formAction:     ["'self'"],
        frameAncestors: ["'none'"],
        baseUri:        ["'none'"],
        objectSrc:      ["'none'"],
        workerSrc:               ["'self'", "blob:"],
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
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xContentTypeOptions: true,
    xFrameOptions: { action: 'deny' },
  })(req, res, next);
});

// JSON body parser (needed for POST endpoints)
app.use(express.json());

// LOW-05: add X-Request-ID correlation header to every response
app.use((_req, res, next) => {
  res.setHeader('X-Request-ID', randomBytes(8).toString('hex'));
  next();
});

// LOW-03: prevent MIME-sniffing on API JSON responses by setting Content-Disposition
app.use((req, res, next) => {
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
app.use(express.static(distPath, { index: false }));

// SPA fallback: inject CSP nonce into index.html before serving.
// Vite builds a small inline <script> for module preloading; we replace the
// placeholder attribute `nonce=""` with the real per-request nonce so the
// browser accepts it without 'unsafe-inline'.
import { readFileSync, writeFileSync, existsSync } from 'fs';

const indexHtmlPath = path.join(distPath, 'index.html');

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

// Run detect-system.sh and return JSON — requires setup token
app.get('/api/system-info', requireSetupToken, (_req, res) => {
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

// ── Health probe (Phase E) ────────────────────────────────────────────────────
// Opens a transient Unix socket connection to the daemon, sends a Ping,
// and returns 200 OK if the daemon responds or 503 if it is unreachable.
// Consumed by Nginx proxy_next_upstream and external monitoring probes.

app.get('/health', (_req, res) => {
  const socket = net.createConnection(DAEMON_SOCKET);
  let responded = false;

  const fail = (reason) => {
    if (!responded) {
      responded = true;
      socket.destroy();
      res.status(503).json({ status: 'unhealthy', reason });
    }
  };

  socket.setTimeout(3000);
  socket.on('connect', () => {
    if (!responded) {
      responded = true;
      socket.destroy();
      res.status(200).json({ status: 'ok' });
    }
  });
  socket.on('timeout', () => fail('daemon timeout'));
  socket.on('error', (err) => fail(err.message));
});

// ── Mount offline demo-mode API routes ───────────────────────────────────────
mountAuthAndVault(app);

// ─────────────────────────────────────────────────────────────────────────────

app.get('*', (req, res) => {
  let indexHtml;
  try {
    indexHtml = readFileSync(indexHtmlPath, 'utf-8');
  } catch {
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
const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

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

wss.on('connection', (ws, req) => {
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

  ws.on('close', () => daemon.destroy());
  ws.on('error', () => daemon.destroy());
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
