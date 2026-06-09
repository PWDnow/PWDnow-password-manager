// web/tests/vaultRepository.userRows.test.js
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import { randomBytes } from 'crypto';
import { ctx } from '../lib/context.js';
import { FileVaultRepository } from '../lib/vaultRepository.js';
import { writeEncryptedFile } from '../lib/fileCrypto.js';

function userRowsSuite(label, makeRepo) {
  describe(`VaultRepository user-rows — ${label}`, () => {
    it('insertUser then findUserById returns the row', async () => {
      const repo = await makeRepo();
      const id = randomBytes(8).toString('hex');
      const emailHash = randomBytes(16).toString('hex');
      await repo.insertUser({ id, emailHash, passwordHash: 'h', createdAt: Date.now() });
      const u = await repo.findUserById(id);
      assert.ok(u); assert.equal(u.emailHash, emailHash);
    });

    it('insertUser rejects a duplicate emailHash', async () => {
      const repo = await makeRepo();
      const emailHash = randomBytes(16).toString('hex');
      await repo.insertUser({ id: randomBytes(8).toString('hex'), emailHash, passwordHash: 'h' });
      await assert.rejects(
        () => repo.insertUser({ id: randomBytes(8).toString('hex'), emailHash, passwordHash: 'h2' }),
        /exists|duplicate|unique/i,
      );
    });

    it('updateUserById mutates a single user and persists', async () => {
      const repo = await makeRepo();
      const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'old' });
      const ret = await repo.updateUserById(id, (u) => { u.passwordHash = 'new'; return u.id; });
      assert.equal(ret, id);
      assert.equal((await repo.findUserById(id)).passwordHash, 'new');
    });

    it('updateUserById on missing id returns null and does not throw', async () => {
      const repo = await makeRepo();
      assert.equal(await repo.updateUserById('ghost', () => {}), null);
    });

    it('deleteUserById removes the user row', async () => {
      const repo = await makeRepo();
      const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'h' });
      await repo.deleteUserById(id);
      assert.equal(await repo.findUserById(id), null);
    });
  });
}

describe('File backend setup', () => {
  let tmpDir;
  before(async () => {
    tmpDir = path.join(tmpdir(), `urows-${randomBytes(8).toString('hex')}`);
    mkdirSync(tmpDir, { recursive: true });
    ctx.MASTER_KEY = randomBytes(32);
    ctx.DATA_DIR = tmpDir;
    ctx.derivedKeyCache = new Map();
    writeEncryptedFile(path.join(tmpDir, 'users.enc'), 'users/enc', []);
    mkdirSync(path.join(tmpDir, 'vault'), { recursive: true, mode: 0o700 });
  });
  after(() => { if (existsSync(tmpDir)) rmSync(tmpDir, { recursive: true, force: true }); });
  userRowsSuite('File', async () => new FileVaultRepository(tmpDir));
});

export { userRowsSuite };
