// web/tests/postgresVaultRepository.contract.test.js
// Runs the same behavioral contract the FileVaultRepository satisfies, against Postgres.
// Skips entirely unless DATABASE_URL is set.
import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'crypto';

if (!process.env.DATABASE_URL) {
  describe('PostgresVaultRepository (skipped — no DATABASE_URL)', () => { it('skipped', () => {}); });
} else {
  const { PostgresVaultRepository } = await import('../lib/postgresVaultRepository.js');
  const { Envelope } = await import('../lib/envelope.js');
  const { LocalDevKmsProvider } = await import('../lib/kms/localDevKms.js');
  const { query, closePool } = await import('../lib/db/pool.js');

  function makeRepo() {
    return new PostgresVaultRepository(new Envelope(new LocalDevKmsProvider(randomBytes(32))));
  }

  describe('PostgresVaultRepository contract', () => {
    before(async () => { await query('DELETE FROM vault_items'); await query('DELETE FROM users'); });
    after(async () => { await closePool(); });
    beforeEach(async () => { await query('DELETE FROM vault_items'); await query('DELETE FROM users'); });

    it('insertUser + findUserByEmailHash + findUserById', async () => {
      const repo = makeRepo();
      const id = randomBytes(8).toString('hex'); const eh = randomBytes(16).toString('hex');
      await repo.insertUser({ id, emailHash: eh, passwordHash: 'h' });
      assert.equal((await repo.findUserByEmailHash(eh)).id, id);
      assert.equal((await repo.findUserById(id)).emailHash, eh);
    });

    it('insertUser rejects duplicate emailHash', async () => {
      const repo = makeRepo(); const eh = randomBytes(16).toString('hex');
      await repo.insertUser({ id: randomBytes(8).toString('hex'), emailHash: eh, passwordHash: 'h' });
      await assert.rejects(() => repo.insertUser({ id: randomBytes(8).toString('hex'), emailHash: eh, passwordHash: 'x' }), /exists|unique|duplicate/i);
    });

    it('updateUserById mutates one row', async () => {
      const repo = makeRepo(); const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'old' });
      await repo.updateUserById(id, u => { u.passwordHash = 'new'; });
      assert.equal((await repo.findUserById(id)).passwordHash, 'new');
    });

    it('updateUserById persists arbitrary flexible fields via meta jsonb', async () => {
      const repo = makeRepo(); const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'h' });
      await repo.updateUserById(id, u => {
        u.loginHints = { totp: true };
        u.duressEnforce = { armed: true, maxAttempts: 3 };
        u.fingerprintLog = [{ id: 'fp1', lastSeen: 1 }];
        u.revocationEpoch = 2;
      });
      const u = await repo.findUserById(id);
      assert.deepEqual(u.loginHints, { totp: true });
      assert.deepEqual(u.duressEnforce, { armed: true, maxAttempts: 3 });
      assert.equal(u.fingerprintLog.length, 1);
      assert.equal(u.revocationEpoch, 2);
    });

    it('updateUserById on missing id returns null; fn returning false skips write', async () => {
      const repo = makeRepo(); const id = randomBytes(8).toString('hex');
      assert.equal(await repo.updateUserById('ghost', () => {}), null);
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'h' });
      const r = await repo.updateUserById(id, u => { u.passwordHash = 'should-not-save'; return false; });
      assert.equal(r, false);
      assert.equal((await repo.findUserById(id)).passwordHash, 'h');
    });

    it('setResource/getResource round-trip (encrypted at rest)', async () => {
      const repo = makeRepo(); const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'h' });
      const data = [{ id: '1', name: 'github', secret: 'PLAINTEXT_MARKER' }];
      await repo.setResource(id, 'credentials', data);
      assert.deepEqual(await repo.getResource(id, 'credentials'), data);
      const raw = await query('SELECT ciphertext FROM vault_items WHERE user_id=$1 AND name=$2', [id, 'credentials']);
      assert.ok(!raw.rows[0].ciphertext.toString('utf8').includes('PLAINTEXT_MARKER'), 'must be ciphertext at rest');
    });

    it('setResource UPSERT bumps version', async () => {
      const repo = makeRepo(); const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'h' });
      await repo.setResource(id, 'folders', [{ id: 'a' }]);
      await repo.setResource(id, 'folders', [{ id: 'a' }, { id: 'b' }]);
      const v = await query('SELECT version FROM vault_items WHERE user_id=$1 AND name=$2', [id, 'folders']);
      assert.equal(v.rows[0].version, 2);
      assert.equal((await repo.getResource(id, 'folders')).length, 2);
    });

    it('getResource returns null when absent', async () => {
      const repo = makeRepo(); const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'h' });
      assert.equal(await repo.getResource(id, 'folders'), null);
    });

    it('sessions roundtrip via loadSessions/saveSessions', async () => {
      const repo = makeRepo(); const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'h' });
      assert.deepEqual(await repo.loadSessions(id), []);
      await repo.saveSessions(id, [{ jti: 'abc', id: 'abc', isCurrent: true }]);
      const s = await repo.loadSessions(id); assert.equal(s.length, 1); assert.equal(s[0].jti, 'abc');
    });

    it('deleteResource + deleteUserById (cascades items)', async () => {
      const repo = makeRepo(); const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'h' });
      await repo.setResource(id, 'folders', [{ id: 'f' }]);
      await repo.deleteResource(id, 'folders');
      assert.equal(await repo.getResource(id, 'folders'), null);
      await repo.setResource(id, 'credentials', [{ id: 'c' }]);
      await repo.deleteUserById(id);
      assert.equal(await repo.findUserById(id), null);
      const left = await query('SELECT count(*)::int AS n FROM vault_items WHERE user_id=$1', [id]);
      assert.equal(left.rows[0].n, 0, 'vault_items must cascade-delete with the user');
    });
  });
}
