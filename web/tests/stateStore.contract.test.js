// StateStore contract tests — same suite runs against every implementation.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryStateStore } from '../lib/stateStore.js';

function contractSuite(label, makeStore) {
  describe(`StateStore contract — ${label}`, () => {
    it('get returns null for missing key', async () => {
      const s = makeStore();
      assert.equal(await s.get('no-such-key'), null);
    });

    it('set and get roundtrip', async () => {
      const s = makeStore();
      await s.set('k', 'hello');
      assert.equal(await s.get('k'), 'hello');
    });

    it('set stringifies numbers', async () => {
      const s = makeStore();
      await s.set('n', 42);
      assert.equal(await s.get('n'), '42');
    });

    it('del removes the key', async () => {
      const s = makeStore();
      await s.set('k', 'v');
      await s.del('k');
      assert.equal(await s.get('k'), null);
    });

    it('del on non-existent key does not throw', async () => {
      const s = makeStore();
      await assert.doesNotReject(() => s.del('ghost'));
    });

    it('incrExpire returns 1 on first call', async () => {
      const s = makeStore();
      assert.equal(await s.incrExpire('counter', 60_000), 1);
    });

    it('incrExpire increments monotonically', async () => {
      const s = makeStore();
      await s.incrExpire('c2', 60_000);
      await s.incrExpire('c2', 60_000);
      assert.equal(await s.incrExpire('c2', 60_000), 3);
    });

    it('incrExpire keys are independent', async () => {
      const s = makeStore();
      await s.incrExpire('a', 60_000);
      await s.incrExpire('a', 60_000);
      await s.incrExpire('b', 60_000);
      assert.equal(await s.incrExpire('a', 60_000), 3);
      assert.equal(await s.incrExpire('b', 60_000), 2);
    });

    it('decr floors at 0', async () => {
      const s = makeStore();
      assert.equal(await s.decr('x'), 0);
    });

    it('decr decrements counter set by incrExpire', async () => {
      const s = makeStore();
      await s.incrExpire('gauge', 60_000);
      await s.incrExpire('gauge', 60_000);
      await s.incrExpire('gauge', 60_000); // = 3
      assert.equal(await s.decr('gauge'), 2);
      assert.equal(await s.decr('gauge'), 1);
    });

    it('getdel returns value and deletes key', async () => {
      const s = makeStore();
      await s.set('otp', 'secret');
      assert.equal(await s.getdel('otp'), 'secret');
      assert.equal(await s.get('otp'), null);
    });

    it('getdel on missing key returns null', async () => {
      const s = makeStore();
      assert.equal(await s.getdel('nope'), null);
    });

    it('getdel is single-use (only one of two concurrent calls gets the value)', async () => {
      const s = makeStore();
      await s.set('once', 'val');
      const [a, b] = await Promise.all([s.getdel('once'), s.getdel('once')]);
      const results = [a, b].filter(v => v !== null);
      assert.equal(results.length, 1, 'exactly one caller should get the value');
      assert.equal(results[0], 'val');
    });
  });
}

contractSuite('InMemory', () => new InMemoryStateStore());

if (process.env.REDIS_URL) {
  const { RedisStateStore } = await import('../lib/redisStateStore.js');
  contractSuite('Redis', () => new RedisStateStore(process.env.REDIS_URL));
}
