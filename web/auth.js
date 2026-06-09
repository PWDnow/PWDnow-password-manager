import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { randomBytes } from 'crypto';
import path from 'path';

import { ctx } from './lib/context.js';
import { derivedKey, writeEncryptedFile } from './lib/fileCrypto.js';
import { loadIpPolicy, ipBlockingMiddleware, getServerPublicIp as _getServerPublicIp } from './lib/audit.js';
import { IpIntelligenceService } from './ipIntelligence.js';
import { mountAuthRoutes } from './routes/authRoutes.js';
import { mountVaultRoutes } from './routes/vaultRoutes.js';
import { validateEnvSmtp } from './lib/smtpConfig.js';
import { InMemoryStateStore } from './lib/stateStore.js';
import { FileVaultRepository } from './lib/vaultRepository.js';

// ── Module initialisation ─────────────────────────────────────────────────────

export async function initAuth({ dataDir }) {
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

  // ── StateStore ─────────────────────────────────────────────────────────────
  // Default: in-memory (self-host / single-node, zero config).
  // Upgrade to Redis when REDIS_URL is set — makes rate limits cluster-aware.
  ctx.stateStore = new InMemoryStateStore();
  if (process.env.REDIS_URL) {
    try {
      const { RedisStateStore } = await import('./lib/redisStateStore.js');
      ctx.stateStore = new RedisStateStore(process.env.REDIS_URL);
      const redisDisplay = process.env.REDIS_URL.replace(/:\/\/[^@]*@/, '://*@');
      console.log(`[StateStore] Redis: ${redisDisplay}`);
    } catch (e) {
      console.warn('[StateStore] Redis init failed, using in-memory:', e.message);
    }
  }

  // ── VaultRepository ────────────────────────────────────────────────────────
  // Backend selection: VAULT_BACKEND = 'file' (default, self-host) | 'postgres' | 'dual'.
  const backend = (process.env.VAULT_BACKEND || 'file').toLowerCase();
  const fileRepo = new FileVaultRepository(ctx.DATA_DIR);
  if (backend === 'file') {
    ctx.vaultRepository = fileRepo;
  } else {
    const { createKmsProvider } = await import('./lib/kms/kmsProvider.js');
    const { Envelope } = await import('./lib/envelope.js');
    const { PostgresVaultRepository } = await import('./lib/postgresVaultRepository.js');
    ctx.kms = await createKmsProvider();
    ctx.envelope = new Envelope(ctx.kms);
    const pgRepo = new PostgresVaultRepository(ctx.envelope);
    if (backend === 'postgres') {
      ctx.vaultRepository = pgRepo;
    } else if (backend === 'dual') {
      const { DualWriteVaultRepository } = await import('./lib/dualWriteVaultRepository.js');
      ctx.vaultRepository = new DualWriteVaultRepository(fileRepo, pgRepo); // file primary
    } else {
      throw new Error(`unknown VAULT_BACKEND: ${backend}`);
    }
    console.log(`[VaultRepository] backend=${backend} kms=${process.env.KMS_PROVIDER || 'local'}`);
  }

  // Pre-warm to avoid mid-request outbound network calls on the first login.
  _getServerPublicIp().catch(() => {});
  // Pre-populate the derived-key cache for the two hottest paths.
  derivedKey('jwe/session', 32);
  derivedKey('users/enc', 32);
  validateEnvSmtp().catch(e => console.error('[smtp] Startup validation error:', e.message));
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
