// RedisStateStore — Redis-backed StateStore implementation.
// Implements the same duck-typed interface as InMemoryStateStore.
import Redis from 'ioredis';

// Atomic INCR + EXPIRE-on-create. TTL is set only the first time the key is created
// (count == 1), preserving sliding-window semantics identical to InMemoryStateStore.
const INCR_EXPIRE_SCRIPT = `
  local cur = redis.call('INCR', KEYS[1])
  if cur == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
  return cur
`;

export class RedisStateStore {
  constructor(redisUrl) {
    this._r = new Redis(redisUrl, {
      enableOfflineQueue: false,
      lazyConnect: true,
      maxRetriesPerRequest: 1,
    });
    this._r.connect().catch(e => console.error('[RedisStateStore] connect error:', e.message));
  }

  async get(key) {
    const val = await this._r.get(key);
    return val ?? null;
  }

  async set(key, value, ttlMs = 0) {
    if (ttlMs > 0) {
      await this._r.set(key, String(value), 'PX', ttlMs);
    } else {
      await this._r.set(key, String(value));
    }
  }

  async del(key) { await this._r.del(key); }

  async incrExpire(key, ttlMs) {
    const result = await this._r.eval(INCR_EXPIRE_SCRIPT, 1, key, String(ttlMs));
    return Number(result);
  }

  async decr(key) {
    const val = await this._r.decr(key);
    if (val < 0) { await this._r.set(key, '0'); return 0; }
    return val;
  }

  async getdel(key) {
    try {
      const val = await this._r.getdel(key);
      return val ?? null;
    } catch {
      // Redis < 6.2 fallback
      const val = await this._r.get(key);
      if (val === null) return null;
      await this._r.del(key);
      return val;
    }
  }

  async quit() { await this._r.quit(); }
}
