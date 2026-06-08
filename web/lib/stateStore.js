// StateStore — ephemeral key-value store with TTL, atomic increment, and single-use get.
//
// Interface (duck-typed):
//   async get(key)                       → string | null
//   async set(key, value, ttlMs = 0)     → void   (ttlMs=0 = no expiry)
//   async del(key)                       → void
//   async incrExpire(key, ttlMs)         → number (atomic increment; sets TTL only on first call)
//   async decr(key)                      → number (floor=0)
//   async getdel(key)                    → string | null (atomic get+delete)

export class InMemoryStateStore {
  constructor() {
    this._map = new Map(); // key → { value: string, expiresAt: number | 0, timer: Timer | null }
  }

  async get(key) {
    const e = this._map.get(key);
    if (!e) return null;
    if (e.expiresAt && Date.now() > e.expiresAt) { this._evict(key); return null; }
    return e.value;
  }

  async set(key, value, ttlMs = 0) {
    this._evict(key);
    const expiresAt = ttlMs > 0 ? Date.now() + ttlMs : 0;
    const timer = ttlMs > 0 ? setTimeout(() => this._evict(key), ttlMs) : null;
    if (timer) timer.unref();
    this._map.set(key, { value: String(value), expiresAt, timer });
  }

  async del(key) { this._evict(key); }

  async incrExpire(key, ttlMs) {
    const e = this._map.get(key);
    const now = Date.now();
    if (!e || (e.expiresAt && now > e.expiresAt)) {
      this._evict(key);
      await this.set(key, '1', ttlMs);
      return 1;
    }
    const newVal = Number(e.value) + 1;
    e.value = String(newVal);
    return newVal;
  }

  async decr(key) {
    const e = this._map.get(key);
    if (!e) return 0;
    if (e.expiresAt && Date.now() > e.expiresAt) { this._evict(key); return 0; }
    const newVal = Math.max(0, Number(e.value) - 1);
    e.value = String(newVal);
    return newVal;
  }

  async getdel(key) {
    // Inline get+evict without any internal await so this is atomic in JS's
    // single-threaded event loop — no concurrent caller can read between the
    // check and the delete.
    const e = this._map.get(key);
    if (!e) return null;
    if (e.expiresAt && Date.now() > e.expiresAt) { this._evict(key); return null; }
    const val = e.value;
    this._evict(key);
    return val;
  }

  _evict(key) {
    const e = this._map.get(key);
    if (!e) return;
    if (e.timer) clearTimeout(e.timer);
    this._map.delete(key);
  }

  _size() { return this._map.size; }
}

export async function createStateStore(redisUrl) {
  if (redisUrl) {
    const { RedisStateStore } = await import('./redisStateStore.js');
    return new RedisStateStore(redisUrl);
  }
  return new InMemoryStateStore();
}
