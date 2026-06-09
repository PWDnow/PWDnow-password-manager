// web/lib/dualWriteVaultRepository.js
// Migration shim: file is primary (reads + authoritative writes); Postgres is mirrored.
// Mirror failures are logged, never thrown, so the live file path is never degraded.
export class DualWriteVaultRepository {
  constructor(primary, secondary) { this._p = primary; this._s = secondary; }

  get kind() { return 'dual'; }

  async _mirror(op, fn) { try { await fn(); } catch (e) { console.error(`[dual-write] mirror ${op} failed:`, e.message); } }

  // reads → primary
  findUserByEmailHash(x) { return this._p.findUserByEmailHash(x); }
  findUserById(x) { return this._p.findUserById(x); }
  loadSessions(uid) { return this._p.loadSessions(uid); }
  getResource(uid, n) { return this._p.getResource(uid, n); }

  // writes → primary then mirror
  async insertUser(user) {
    const r = await this._p.insertUser(user);
    await this._mirror('insertUser', () => this._s.insertUser(user));
    return r;
  }
  async updateUserById(id, fn) {
    const r = await this._p.updateUserById(id, fn);
    await this._mirror('updateUserById', async () => {
      const updated = await this._p.findUserById(id);
      if (updated) {
        await this._s.updateUserById(id, (u) => {
          // Copy every flexible + authoritative field the primary now holds.
          for (const k of Object.keys(updated)) {
            if (k === 'wrappedDek' || k === 'kmsKeyId') continue; // owned by the secondary's KMS
            u[k] = updated[k];
          }
        });
      }
    });
    return r;
  }
  async deleteUserById(id) { await this._p.deleteUserById(id); await this._mirror('deleteUserById', () => this._s.deleteUserById(id)); }
  async saveSessions(uid, list) { await this._p.saveSessions(uid, list); await this._mirror('saveSessions', () => this._s.saveSessions(uid, list)); }
  async setResource(uid, n, v) { await this._p.setResource(uid, n, v); await this._mirror('setResource', () => this._s.setResource(uid, n, v)); }
  async deleteResource(uid, n) { await this._p.deleteResource(uid, n); await this._mirror('deleteResource', () => this._s.deleteResource(uid, n)); }
  async deleteUserData(uid) { await this._p.deleteUserData(uid); await this._mirror('deleteUserData', () => this._s.deleteUserData(uid)); }
  async withUserTransaction(fn) { return this._p.withUserTransaction(fn); }
}
