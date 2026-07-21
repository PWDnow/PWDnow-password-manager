// web/tests/kms.selfhost.contract.test.js
import { randomBytes } from 'crypto';
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, chmodSync, writeFileSync, statSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import { kmsContractSuite } from './helpers/kmsContractSuite.js';
import {
  SelfHostKmsProvider,
  generateSelfHostMasterKeyFile,
  loadSelfHostMasterKey,
} from '../lib/kms/selfHostKms.js';

kmsContractSuite('SelfHost (direct key)', async () => new SelfHostKmsProvider(randomBytes(32)));

describe('SelfHostKms master-key file (raw, no passphrase)', () => {
  let dir;
  const cleanupDirs = [];
  function newDir() {
    const d = mkdtempSync(path.join(tmpdir(), 'selfhost-kms-'));
    cleanupDirs.push(d);
    return d;
  }
  after(() => { for (const d of cleanupDirs) rmSync(d, { recursive: true, force: true }); });

  it('generate then load round-trips a 32-byte key', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath });
    const key = await loadSelfHostMasterKey({ keyPath });
    assert.ok(Buffer.isBuffer(key));
    assert.equal(key.length, 32);
  });

  it('generated file is created with mode 0600', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath });
    const mode = statSync(keyPath).mode & 0o777;
    assert.equal(mode, 0o600);
  });

  it('refuses to load a group-readable key file', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath });
    chmodSync(keyPath, 0o640);
    await assert.rejects(() => loadSelfHostMasterKey({ keyPath }), /group\/world readable/);
  });

  it('refuses to load a world-readable key file', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath });
    chmodSync(keyPath, 0o644);
    await assert.rejects(() => loadSelfHostMasterKey({ keyPath }), /group\/world readable/);
  });

  it('refuses to load a file that is not exactly 32 bytes', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'bad.key');
    writeFileSync(keyPath, Buffer.from('too short'), { mode: 0o600 });
    await assert.rejects(() => loadSelfHostMasterKey({ keyPath }), /32 bytes/);
  });
});
