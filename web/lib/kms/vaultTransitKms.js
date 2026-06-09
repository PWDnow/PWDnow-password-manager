// web/lib/kms/vaultTransitKms.js
// HashiCorp Vault Transit adapter. The DEK never leaves Vault in plaintext form on
// disk; Vault holds the CMK. We send base64(DEK) to /transit/encrypt and receive a
// "vault:vN:..." ciphertext string. keyId records the key + version for rotation.
//
// Requires: VAULT_ADDR (https://...), VAULT_TOKEN, key created via:
//   vault secrets enable transit
//   vault write -f transit/keys/pwdnow-dek type=aes256-gcm96
const DEFAULT_TIMEOUT_MS = 4000;

export class VaultTransitKmsProvider {
  constructor({ addr, token, keyName, timeoutMs = DEFAULT_TIMEOUT_MS }) {
    if (!addr || !token || !keyName) throw new Error('VaultTransitKmsProvider needs addr, token, keyName');
    this._addr = addr.replace(/\/+$/, '');
    this._token = token;
    this._key = keyName;
    this._timeoutMs = timeoutMs;
  }

  async _post(pathSuffix, body) {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), this._timeoutMs);
    try {
      const r = await fetch(`${this._addr}/v1/transit/${pathSuffix}`, {
        method: 'POST',
        headers: { 'X-Vault-Token': this._token, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: ac.signal,
      });
      if (!r.ok) throw new Error(`vault transit ${pathSuffix} -> HTTP ${r.status}`);
      return (await r.json()).data;
    } finally { clearTimeout(t); }
  }

  async wrapDek(dek) {
    const data = await this._post(`encrypt/${this._key}`, { plaintext: dek.toString('base64') });
    // ciphertext form: "vault:v3:base64..."; keyId records the version prefix for rotation.
    const ciphertext = data.ciphertext;
    const version = ciphertext.split(':')[1] || 'v?';
    return { wrapped: Buffer.from(ciphertext, 'utf8'), keyId: `${this._key}:${version}` };
  }

  async unwrapDek(wrapped, _keyId) {
    const data = await this._post(`decrypt/${this._key}`, { ciphertext: wrapped.toString('utf8') });
    const dek = Buffer.from(data.plaintext, 'base64');
    if (dek.length !== 32) throw new Error('unwrapped DEK is not 32 bytes');
    return dek;
  }
}
