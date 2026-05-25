import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { randomBytes } from 'crypto';
import path from 'path';

import { ctx } from './lib/context.js';
import { derivedKey, writeEncryptedFile } from './lib/fileCrypto.js';
import { loadIpPolicy, ipBlockingMiddleware, getServerPublicIp as _getServerPublicIp } from './lib/audit.js';
import { IpIntelligenceService } from './ipIntelligence.js';
import { mountAuthRoutes } from './routes/authRoutes.js';
import { mountVaultRoutes } from './routes/vaultRoutes.js';

// ── Module initialisation ─────────────────────────────────────────────────────

export function initAuth({ dataDir }) {
  ctx.DATA_DIR = dataDir;
  ctx.derivedKeyCache.clear(); // clear on re-init in case MASTER_KEY changes
  if (!existsSync(ctx.DATA_DIR)) mkdirSync(ctx.DATA_DIR, { recursive: true, mode: 0o700 });

  const keyPath = path.join(ctx.DATA_DIR, '.master_key');
  if (existsSync(keyPath)) {
    ctx.MASTER_KEY = readFileSync(keyPath);
    if (ctx.MASTER_KEY.length !== 32) throw new Error('master key file is not 32 bytes');
  } else {
    ctx.MASTER_KEY = randomBytes(32);
    writeFileSync(keyPath, ctx.MASTER_KEY, { mode: 0o400, flag: 'wx' });
  }

  const usersFile = path.join(ctx.DATA_DIR, 'users.enc');
  if (!existsSync(usersFile)) writeEncryptedFile(usersFile, 'users/enc', []);
  const vaultDir = path.join(ctx.DATA_DIR, 'vault');
  if (!existsSync(vaultDir)) mkdirSync(vaultDir, { recursive: true, mode: 0o700 });

  ctx.ipIntel = new IpIntelligenceService(process.env.IPREGISTRY_API_KEY ?? '', ctx.DATA_DIR);
  ctx.ipPolicy = loadIpPolicy();

  // Pre-warm to avoid mid-request outbound network calls on the first login.
  _getServerPublicIp().catch(() => {});
  // Pre-populate the derived-key cache for the two hottest paths.
  derivedKey('jwe/session', 32);
  derivedKey('users/enc', 32);
}

// ── Re-export getServerPublicIp so server.js import is unchanged ──────────────

export async function getServerPublicIp() {
  return _getServerPublicIp();
}

// ── Public route mounter ──────────────────────────────────────────────────────

export function mountAuthAndVault(app) {
  app.use(ipBlockingMiddleware);
  mountAuthRoutes(app);
  mountVaultRoutes(app);
}
