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
  createSelfHostKmsProvider,
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

describe('SelfHostKms master-key file (passphrase-wrapped)', () => {
  let dir;
  const cleanupDirs = [];
  function newDir() {
    const d = mkdtempSync(path.join(tmpdir(), 'selfhost-kms-pw-'));
    cleanupDirs.push(d);
    return d;
  }
  after(() => { for (const d of cleanupDirs) rmSync(d, { recursive: true, force: true }); });

  it('generate then load with the correct passphrase round-trips a 32-byte key', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath, passphrase: 'correct horse battery staple' });
    const key = await loadSelfHostMasterKey({ keyPath, passphrase: 'correct horse battery staple' });
    assert.ok(Buffer.isBuffer(key));
    assert.equal(key.length, 32);
  });

  it('the same master key is recovered as would be with a raw (non-passphrase) file of the same content', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath, passphrase: 'hunter2-hunter2-hunter2' });
    const a = await loadSelfHostMasterKey({ keyPath, passphrase: 'hunter2-hunter2-hunter2' });
    const b = await loadSelfHostMasterKey({ keyPath, passphrase: 'hunter2-hunter2-hunter2' });
    assert.ok(a.equals(b), 'loading twice with the same passphrase must yield the same key');
  });

  it('wrong passphrase fails to unwrap', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath, passphrase: 'right-passphrase' });
    await assert.rejects(() => loadSelfHostMasterKey({ keyPath, passphrase: 'wrong-passphrase' }));
  });

  it('passphrase-wrapped file is still mode 0600', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath, passphrase: 'whatever' });
    assert.equal(statSync(keyPath).mode & 0o777, 0o600);
  });

  it('resulting provider round-trips a DEK end to end', async () => {
    dir = newDir();
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath, passphrase: 'end-to-end-check' });
    const masterKey = await loadSelfHostMasterKey({ keyPath, passphrase: 'end-to-end-check' });
    const kms = new SelfHostKmsProvider(masterKey);
    const dek = randomBytes(32);
    const { wrapped, keyId } = await kms.wrapDek(dek);
    assert.ok((await kms.unwrapDek(wrapped, keyId)).equals(dek));
  });
});

kmsContractSuite('SelfHost (factory, no passphrase)', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'selfhost-kms-factory-'));
  const keyPath = path.join(dir, 'master.key');
  await generateSelfHostMasterKeyFile({ keyPath });
  return createSelfHostKmsProvider({ keyPath });
});

kmsContractSuite('SelfHost (factory, passphrase)', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'selfhost-kms-factory-pw-'));
  const keyPath = path.join(dir, 'master.key');
  const passphrase = 'factory-suite-passphrase';
  await generateSelfHostMasterKeyFile({ keyPath, passphrase });
  return createSelfHostKmsProvider({ keyPath, passphrase });
});

import { createKmsProvider } from '../lib/kms/kmsProvider.js';

describe('createKmsProvider(KMS_PROVIDER=selfhost)', () => {
  it('builds a working SelfHostKmsProvider from env vars', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'selfhost-kms-env-'));
    const keyPath = path.join(dir, 'master.key');
    await generateSelfHostMasterKeyFile({ keyPath });

    const prevProvider = process.env.KMS_PROVIDER;
    const prevKeyPath = process.env.SELF_HOST_KMS_KEY_PATH;
    process.env.KMS_PROVIDER = 'selfhost';
    process.env.SELF_HOST_KMS_KEY_PATH = keyPath;
    try {
      const kms = await createKmsProvider();
      const dek = randomBytes(32);
      const { wrapped, keyId } = await kms.wrapDek(dek);
      assert.ok((await kms.unwrapDek(wrapped, keyId)).equals(dek));
    } finally {
      process.env.KMS_PROVIDER = prevProvider;
      if (prevKeyPath === undefined) delete process.env.SELF_HOST_KMS_KEY_PATH;
      else process.env.SELF_HOST_KMS_KEY_PATH = prevKeyPath;
    }
  });

  it('throws a clear error when SELF_HOST_KMS_KEY_PATH is missing', async () => {
    const prevProvider = process.env.KMS_PROVIDER;
    const prevKeyPath = process.env.SELF_HOST_KMS_KEY_PATH;
    process.env.KMS_PROVIDER = 'selfhost';
    delete process.env.SELF_HOST_KMS_KEY_PATH;
    try {
      await assert.rejects(() => createKmsProvider(), /SELF_HOST_KMS_KEY_PATH/);
    } finally {
      process.env.KMS_PROVIDER = prevProvider;
      if (prevKeyPath !== undefined) process.env.SELF_HOST_KMS_KEY_PATH = prevKeyPath;
    }
  });
});
