// web/scripts/backfill-to-postgres.js
// Idempotent migrator: auth_data/ (file backend) → Postgres (per-user envelope DEK).
//
// Usage:
//   DATABASE_URL=postgres://...  PGSSL=disable \
//   KMS_PROVIDER=local LOCAL_KMS_KEY=$(openssl rand -hex 32) \
//   AUTH_DATA_DIR=../auth_data  node scripts/backfill-to-postgres.js
//
// ⚠️ The KMS key (LOCAL_KMS_KEY or the Vault Transit key) used here MUST be the same
//    one the server uses afterward, or per-user DEKs will not unwrap. In production use
//    KMS_PROVIDER=vault for both so the key authority is shared.
import { ctx } from '../lib/context.js';
import { readFileSync, existsSync, readdirSync } from 'fs';
import path from 'path';
import { FileVaultRepository } from '../lib/vaultRepository.js';
import { PostgresVaultRepository } from '../lib/postgresVaultRepository.js';
import { Envelope } from '../lib/envelope.js';
import { createKmsProvider } from '../lib/kms/kmsProvider.js';
import { loadUsers, userVaultDir } from '../lib/fileCrypto.js';
import { closePool } from '../lib/db/pool.js';

const RESOURCES = [
  'credentials', 'folders', 'asset_holder', 'profile', 'mfa_config', 'sessions',
  'emergency', 'emergency_requests', 'audit_log', 'smtp_config',
  'travel_vault', 'travel_config', 'duress_config',
];

async function main() {
  const dataDir = path.resolve(process.env.AUTH_DATA_DIR || '../auth_data');
  ctx.DATA_DIR = dataDir;
  ctx.derivedKeyCache = new Map();
  const keyPath = path.join(dataDir, '.master_key');
  if (!existsSync(keyPath)) throw new Error(`no .master_key in ${dataDir}`);
  ctx.MASTER_KEY = readFileSync(keyPath);

  const fileRepo = new FileVaultRepository(dataDir);
  const pgRepo = new PostgresVaultRepository(new Envelope(await createKmsProvider()));

  const users = loadUsers();
  console.log(`[backfill] ${users.length} users in ${dataDir}`);
  let migrated = 0, skipped = 0;

  for (const u of users) {
    const existing = await pgRepo.findUserById(u.id);
    if (!existing) {
      // Carry the full user object so flexible fields (loginHints, mfaEnforce, …) land in meta.
      await pgRepo.insertUser(u);
    } else { skipped++; }

    // Discover resource names actually present on disk (covers any not in RESOURCES).
    const dir = userVaultDir(u.id);
    const present = existsSync(dir)
      ? readdirSync(dir).filter(f => f.endsWith('.enc')).map(f => f.replace(/\.enc$/, ''))
      : [];
    const names = [...new Set([...RESOURCES, ...present])];

    for (const name of names) {
      const value = await fileRepo.getResource(u.id, name);
      if (value !== null && value !== undefined) await pgRepo.setResource(u.id, name, value);
    }
    migrated++;
    if (migrated % 100 === 0) console.log(`[backfill] ${migrated}/${users.length}`);
  }
  console.log(`[backfill] done. migrated=${migrated} pre-existing-users=${skipped}`);
  await closePool();
}

main().catch(e => { console.error('[backfill] FAILED:', e); process.exitCode = 1; });
