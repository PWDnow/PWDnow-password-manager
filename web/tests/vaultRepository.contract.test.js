// VaultRepository contract tests — runs against FileVaultRepository.
// Bootstraps a minimal ctx so fileCrypto.js key derivation works in isolation.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import { randomBytes } from 'crypto';

import { ctx } from '../lib/context.js';
import { FileVaultRepository } from '../lib/vaultRepository.js';
import { writeEncryptedFile, userVaultDir } from '../lib/fileCrypto.js';

function mkTmpDir() {
  const d = path.join(tmpdir(), `vr-test-${randomBytes(8).toString('hex')}`);
  mkdirSync(d, { recursive: true });
  return d;
}

function bootstrapCtx(dataDir) {
  ctx.MASTER_KEY = randomBytes(32);
  ctx.DATA_DIR = dataDir;
  ctx.derivedKeyCache = new Map();
  writeEncryptedFile(path.join(dataDir, 'users.enc'), 'users/enc', []);
  mkdirSync(path.join(dataDir, 'vault'), { recursive: true, mode: 0o700 });
}

describe('VaultRepository contract — File', () => {
  let repo;
  let tmpDir;

  before(() => {
    tmpDir = mkTmpDir();
    bootstrapCtx(tmpDir);
    repo = new FileVaultRepository(tmpDir);
  });

  after(() => {
    if (existsSync(tmpDir)) rmSync(tmpDir, { recursive: true, force: true });
  });

  it('findUserByEmailHash returns null when no users', async () => {
    assert.equal(await repo.findUserByEmailHash('any'), null);
  });

  it('findUserById returns null when no users', async () => {
    assert.equal(await repo.findUserById('any'), null);
  });

  it('withUserTransaction creates and retrieves a user', async () => {
    const id = randomBytes(8).toString('hex');
    const emailHash = randomBytes(16).toString('hex');
    await repo.withUserTransaction(users => { users.push({ id, emailHash, passwordHash: 'hash123' }); });
    const found = await repo.findUserByEmailHash(emailHash);
    assert.ok(found, 'should find user by emailHash');
    assert.equal(found.id, id);
  });

  it('findUserById works after insert', async () => {
    const id = randomBytes(8).toString('hex');
    const emailHash = randomBytes(16).toString('hex');
    await repo.withUserTransaction(users => { users.push({ id, emailHash, passwordHash: 'h' }); });
    const found = await repo.findUserById(id);
    assert.ok(found);
    assert.equal(found.emailHash, emailHash);
  });

  it('withUserTransaction returning false skips save', async () => {
    let calls = 0;
    const result = await repo.withUserTransaction(users => { calls++; return false; });
    assert.equal(result, false);
    assert.equal(calls, 1);
  });

  it('sessions roundtrip: load empty, save, reload', async () => {
    const uid = randomBytes(8).toString('hex');
    const dir = userVaultDir(uid);
    mkdirSync(dir, { recursive: true, mode: 0o700 });

    const empty = await repo.loadSessions(uid);
    assert.deepEqual(empty, []);

    const sessions = [{ jti: 'abc', id: 'abc', timestamp: Date.now(), deviceName: 'Chrome', ip: '1234', isCurrent: true }];
    await repo.saveSessions(uid, sessions);
    const loaded = await repo.loadSessions(uid);
    assert.equal(loaded.length, 1);
    assert.equal(loaded[0].jti, 'abc');
  });

  it('getResource returns null when absent', async () => {
    const uid = randomBytes(8).toString('hex');
    assert.equal(await repo.getResource(uid, 'credentials'), null);
  });

  it('setResource and getResource roundtrip', async () => {
    const uid = randomBytes(8).toString('hex');
    const data = [{ id: '1', name: 'github', username: 'user' }];
    await repo.setResource(uid, 'credentials', data);
    const loaded = await repo.getResource(uid, 'credentials');
    assert.deepEqual(loaded, data);
  });

  it('deleteResource removes the file', async () => {
    const uid = randomBytes(8).toString('hex');
    await repo.setResource(uid, 'folders', [{ id: 'f1' }]);
    await repo.deleteResource(uid, 'folders');
    assert.equal(await repo.getResource(uid, 'folders'), null);
  });

  it('deleteUserData removes the whole user directory', async () => {
    const uid = randomBytes(8).toString('hex');
    await repo.setResource(uid, 'credentials', []);
    assert.ok(existsSync(userVaultDir(uid)), 'dir should exist before delete');
    await repo.deleteUserData(uid);
    assert.ok(!existsSync(userVaultDir(uid)), 'dir should be gone after delete');
  });
});
