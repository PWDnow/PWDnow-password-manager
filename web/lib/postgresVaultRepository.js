// web/lib/postgresVaultRepository.js
// Implements the VaultRepository interface against Postgres with per-user envelope ALE.
// Authoritative/indexed user attributes are columns; all other flexible user fields
// round-trip through the `meta jsonb` column so the row model is as extensible as the
// JSON file model it replaces.
import { query, withTx } from './db/pool.js';

const PROMOTED = new Set([
  'id', 'emailHash', 'passwordHash', 'wrappedDek', 'kmsKeyId',
  'wrapMode', 'pwWrapSalt', 'cryptoSalt', 'status', 'createdAt',
]);

// Fields that grant access to the vault or to account recovery/duress paths.
// These are envelope-encrypted under the user's DEK (meta._sealed) instead of
// being stored as plaintext in the meta jsonb column.
const SENSITIVE_META_KEYS = new Set([
  'mfaTotpSecret', 'recoveryKeyHash', 'recoveryKeySalt', 'duressEnforce',
]);

async function rowToUser(env, r) {
  if (!r) return null;
  const meta = r.meta || {};
  const { _sealed, ...restMeta } = meta;
  const base = {
    id: r.id,
    emailHash: r.email_hmac,
    passwordHash: r.password_hash,
    wrappedDek: r.wrapped_dek,            // Buffer
    kmsKeyId: r.kms_key_id,
    wrapMode: r.wrap_mode,
    pwWrapSalt: r.pw_wrap_salt ?? null,
    cryptoSalt: r.crypto_salt ?? null,
    status: r.status,
    createdAt: r.created_at ? new Date(r.created_at).getTime() : meta.createdAt,
  };
  let sealed = {};
  if (_sealed) {
    sealed = await env.decryptResource(base, Buffer.from(_sealed, 'base64'));
  }
  return { ...restMeta, ...sealed, ...base };
}

async function userToMeta(env, user) {
  const meta = {};
  const sealed = {};
  let hasSealed = false;
  for (const k of Object.keys(user)) {
    if (PROMOTED.has(k)) continue;
    if (SENSITIVE_META_KEYS.has(k)) {
      if (user[k] !== undefined) { sealed[k] = user[k]; hasSealed = true; }
    } else {
      meta[k] = user[k];
    }
  }
  if (hasSealed) {
    meta._sealed = (await env.encryptResource(user, sealed)).toString('base64');
  }
  return meta;
}

export class PostgresVaultRepository {
  constructor(envelope) {
    if (!envelope) throw new Error('PostgresVaultRepository requires an Envelope');
    this._env = envelope;
  }

  get kind() { return 'postgres'; }

  async _requireUser(uid) {
    const u = await this.findUserById(uid);
    if (!u) { const e = new Error('user not found'); e.code = 'USER_NOT_FOUND'; throw e; }
    return u;
  }

  async findUserByEmailHash(emailHash) {
    const r = await query('SELECT * FROM users WHERE email_hmac = $1', [emailHash], 'point_read');
    return rowToUser(this._env, r.rows[0]);
  }

  async findUserById(id) {
    const r = await query('SELECT * FROM users WHERE id = $1', [id], 'point_read');
    return rowToUser(this._env, r.rows[0]);
  }

  // New users get a freshly KMS-wrapped DEK provisioned here.
  async insertUser(user) {
    const dek = await this._env.newUserDek();
    const meta = await userToMeta(this._env, { ...user, wrappedDek: dek.wrappedDek, kmsKeyId: dek.kmsKeyId });
    try {
      await query(
        `INSERT INTO users (id, email_hmac, password_hash, wrapped_dek, kms_key_id, wrap_mode, pw_wrap_salt, crypto_salt, status, meta, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9, now())`,
        [user.id, user.emailHash, user.passwordHash, dek.wrappedDek, dek.kmsKeyId,
         dek.wrapMode, dek.pwWrapSalt, user.cryptoSalt ?? null, JSON.stringify(meta)],
        'write',
      );
      return user.id;
    } catch (e) {
      if (e.code === '23505') { const dup = new Error('user exists'); dup.code = 'USER_EXISTS'; throw dup; }
      throw e;
    }
  }

  // Row-locked read-modify-write of one user. fn mutates the user object; if fn returns
  // false the write is skipped (and false is returned). null when no row matched.
  async updateUserById(id, fn) {
    return withTx(async (client) => {
      const r = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [id]);
      if (r.rows.length === 0) return null;
      const user = await rowToUser(this._env, r.rows[0]);
      const ret = fn(user);
      if (ret === false) return false;
      await client.query(
        `UPDATE users SET password_hash=$2, wrap_mode=$3, pw_wrap_salt=$4, crypto_salt=$5, status=$6, meta=$7 WHERE id=$1`,
        [id, user.passwordHash, user.wrapMode, user.pwWrapSalt, user.cryptoSalt ?? null,
         user.status ?? 'active', JSON.stringify(await userToMeta(this._env, user))],
      );
      return ret === undefined ? id : ret;
    });
  }

  async deleteUserById(id) {
    await query('DELETE FROM users WHERE id = $1', [id], 'write'); // vault_items cascade
  }

  // Interface-completeness: load all users, apply fn, diff, write back changed rows.
  // Not a hot path after the route refactor (row methods above are used instead).
  async withUserTransaction(fn) {
    return withTx(async (client) => {
      const r = await client.query('SELECT * FROM users FOR UPDATE');
      const users = await Promise.all(r.rows.map(row => rowToUser(this._env, row)));
      const before = new Map(users.map(u => [u.id, JSON.stringify(u)]));
      const result = await fn(users);
      if (result === false) return result;
      for (const u of users) {
        if (before.get(u.id) !== JSON.stringify(u)) {
          await client.query(
            `UPDATE users SET password_hash=$2, wrap_mode=$3, pw_wrap_salt=$4, crypto_salt=$5, status=$6, meta=$7 WHERE id=$1`,
            [u.id, u.passwordHash, u.wrapMode, u.pwWrapSalt, u.cryptoSalt ?? null, u.status ?? 'active', JSON.stringify(await userToMeta(this._env, u))],
          );
        }
      }
      return result;
    });
  }

  // ── Resources (one row per (user_id, name), envelope-encrypted) ──
  async getResource(uid, name) {
    const user = await this.findUserById(uid);
    if (!user) return null;
    const r = await query('SELECT ciphertext FROM vault_items WHERE user_id=$1 AND name=$2', [uid, name], 'point_read');
    if (r.rows.length === 0) return null;
    return this._env.decryptResource(user, r.rows[0].ciphertext);
  }

  async setResource(uid, name, value) {
    const user = await this._requireUser(uid);
    const blob = await this._env.encryptResource(user, value);
    await query(
      `INSERT INTO vault_items (user_id, name, ciphertext, version, updated_at)
       VALUES ($1,$2,$3,1, now())
       ON CONFLICT (user_id, name) DO UPDATE SET ciphertext=EXCLUDED.ciphertext, version=vault_items.version+1, updated_at=now()`,
      [uid, name, blob],
      'write',
    );
  }

  async deleteResource(uid, name) {
    await query('DELETE FROM vault_items WHERE user_id=$1 AND name=$2', [uid, name], 'write');
  }

  async deleteUserData(uid) {
    await query('DELETE FROM users WHERE id=$1', [uid], 'write'); // cascades vault_items
  }

  // Sessions modeled as a 'sessions' resource row (faithful port; dedicated table is P2).
  async loadSessions(uid) { return (await this.getResource(uid, 'sessions')) ?? []; }
  async saveSessions(uid, list) { await this.setResource(uid, 'sessions', list); }
}
