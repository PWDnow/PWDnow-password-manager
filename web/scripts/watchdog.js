#!/usr/bin/env node
// Health-check watchdog.
// Polls /health every POLL_INTERVAL_MS; if FAILURE_THRESHOLD consecutive checks
// fail, issues `pm2 restart pwdnow`. Runs as a separate PM2 app alongside the
// main server so it survives server restarts and persists across reboots.
//
// Environment variables (all optional, read from .env if present):
//   PORT / SSL_PORT  — port to probe (default 51234)
//   SSL              — 'true' or 'force' → probe HTTPS; otherwise HTTP
//   WATCHDOG_INTERVAL_MS    — poll cadence in ms (default 30000)
//   WATCHDOG_THRESHOLD      — consecutive failures before restart (default 3)

import https from 'https';
import http from 'http';
import { execFileSync } from 'child_process';
import { appendFileSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import dotenv from 'dotenv';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..');

dotenv.config({ path: path.join(root, '.env') });

const SSL_MODE        = (process.env.SSL || 'false').toLowerCase();
const useHttps        = SSL_MODE === 'true' || SSL_MODE === 'force';
const PORT            = parseInt(process.env.SSL_PORT || process.env.PORT || '51234', 10);
const POLL_INTERVAL   = parseInt(process.env.WATCHDOG_INTERVAL_MS  || '30000', 10);
const THRESHOLD       = parseInt(process.env.WATCHDOG_THRESHOLD     || '3',     10);
const HEALTH_URL      = `${useHttps ? 'https' : 'http'}://127.0.0.1:${PORT}/health`;
const LOG_FILE        = path.join(root, 'logs', 'watchdog.log');

mkdirSync(path.join(root, 'logs'), { recursive: true });

function log(msg) {
  const line = `${new Date().toISOString()} [watchdog] ${msg}\n`;
  process.stdout.write(line);
  try { appendFileSync(LOG_FILE, line); } catch { /* non-fatal */ }
}

function checkHealth() {
  // Any HTTP response means the Express process is alive.
  // Only a connection failure (ECONNREFUSED / timeout) means we should restart.
  return new Promise((resolve) => {
    const mod = useHttps ? https : http;
    const req = mod.get(
      HEALTH_URL,
      { rejectUnauthorized: false, timeout: 5000 },
      (res) => { resolve(true); res.resume(); }
    );
    req.on('error',   () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });
}

function restartServer() {
  log(`${THRESHOLD} consecutive failures — attempting PM2 restart`);
  try {
    execFileSync('pm2', ['restart', 'pwdnow'], { stdio: 'pipe', cwd: root });
    log('PM2 restart issued successfully');
  } catch (e) {
    log(`PM2 restart failed (${e.message}) — server will recover on next PM2 auto-restart cycle`);
  }
}

let consecutiveFailures = 0;
let lastState = 'unknown';

async function poll() {
  const ok = await checkHealth();

  if (ok) {
    if (lastState !== 'ok') log(`Server is healthy at ${HEALTH_URL}`);
    consecutiveFailures = 0;
    lastState = 'ok';
  } else {
    consecutiveFailures++;
    log(`Health check failed (${consecutiveFailures}/${THRESHOLD}): ${HEALTH_URL}`);
    lastState = 'fail';
    if (consecutiveFailures >= THRESHOLD) {
      restartServer();
      consecutiveFailures = 0;
    }
  }
}

log(`Watchdog started — probing ${HEALTH_URL} every ${POLL_INTERVAL / 1000}s, threshold ${THRESHOLD}`);

// Stagger first check by 15 s to let the server finish startup.
setTimeout(() => {
  poll();
  setInterval(poll, POLL_INTERVAL);
}, 15_000);
