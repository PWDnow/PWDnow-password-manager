// IP Intelligence service using ipregistry.co
// Set IPREGISTRY_API_KEY in .env — leave blank to disable. Never hard-code keys.

const PRIVATE_IP_RE = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1$|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:)/i;
const IPV6_MAPPED_RE = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/;

export class IpIntelligenceService {
  #apiKey;
  #cache = new Map();   // ip → { record, expiresAt }
  #pending = new Map(); // ip → Promise  (deduplicates concurrent lookups for same IP)
  #CACHE_TTL = 60 * 60 * 1000; // 1 hour
  #MAX_CACHE  = 500;

  constructor(apiKey) {
    this.#apiKey = (apiKey || '').trim();
  }

  isEnabled() {
    return this.#apiKey.length > 0;
  }

  #isPrivate(ip) {
    if (!ip) return true;
    const m = IPV6_MAPPED_RE.exec(ip);
    return PRIVATE_IP_RE.test(m ? m[1] : ip);
  }

  async lookup(ip) {
    if (!this.#apiKey || this.#isPrivate(ip)) return null;

    const cached = this.#cache.get(ip);
    if (cached && Date.now() < cached.expiresAt) return cached.record;

    if (this.#pending.has(ip)) return this.#pending.get(ip);

    const promise = this.#fetchIpInfo(ip).finally(() => this.#pending.delete(ip));
    this.#pending.set(ip, promise);
    return promise;
  }

  async #fetchIpInfo(ip) {
    try {
      const fields = 'security,location,connection,type,hostname';
      const url = `https://api.ipregistry.co/${encodeURIComponent(ip)}?key=${this.#apiKey}&fields=${fields}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timer);

      if (res.status === 429) {
        console.warn('[ipIntel] rate limited — failing open');
        return null;
      }
      if (!res.ok) {
        console.warn('[ipIntel] API error', res.status);
        return null;
      }

      const data = await res.json();
      const record = this.#normalize(ip, data);

      if (this.#cache.size >= this.#MAX_CACHE) {
        this.#cache.delete(this.#cache.keys().next().value);
      }
      this.#cache.set(ip, { record, expiresAt: Date.now() + this.#CACHE_TTL });
      return record;
    } catch (err) {
      console.warn('[ipIntel] lookup failed:', err.message);
      return null;
    }
  }

  #normalize(ip, data) {
    const sec  = data.security   || {};
    const loc  = data.location   || {};
    const conn = data.connection || {};
    const country = loc.country  || {};
    const region  = loc.region   || {};

    const riskFlags = [];
    if (sec.is_tor)      riskFlags.push('tor');
    if (sec.is_proxy)    riskFlags.push('proxy');
    if (sec.is_vpn)      riskFlags.push('vpn');
    if (sec.is_abuser)   riskFlags.push('abuser');
    if (sec.is_attacker) riskFlags.push('attacker');
    if (sec.is_relay)    riskFlags.push('relay');

    return {
      ip,
      country:        country.name  || '',
      countryCode:    country.code  || '',
      countryFlag:    country.flag?.emoji || '',
      city:           loc.city      || '',
      region:         region.name   || '',
      org:            conn.organization || '',
      asn:            conn.asn      || null,
      connectionType: conn.type     || data.type || '',
      hostname:       data.hostname || '',
      isCloudProvider: sec.is_cloud_provider || false,
      isTor:      sec.is_tor       || false,
      isProxy:    sec.is_proxy     || false,
      isVpn:      sec.is_vpn       || false,
      isAbuser:   sec.is_abuser    || false,
      isAttacker: sec.is_attacker  || false,
      isRelay:    sec.is_relay     || false,
      riskFlags,
    };
  }

  isThreat(record, policy) {
    if (!record) return false;
    if (policy.blockTor    && (record.isTor || record.isRelay))       return true;
    if (policy.blockProxy  && record.isProxy)                         return true;
    if (policy.blockVpn    && record.isVpn)                           return true;
    if (policy.blockAbuser && (record.isAbuser || record.isAttacker)) return true;
    return false;
  }

  getRiskFlags(record) {
    return record ? record.riskFlags : [];
  }
}
