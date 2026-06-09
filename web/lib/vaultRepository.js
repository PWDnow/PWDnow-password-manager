// VaultRepository — abstraction layer over the encrypted-file user and vault store.
//
// Interface (duck-typed):
//   async withUserTransaction(fn)          mutate-in-place: fn(users[]) → result | false (false = skip save)
//   async findUserByEmailHash(emailHash)   → user | null
//   async findUserById(id)                 → user | null
//   async loadSessions(uid)               → Session[]
//   async saveSessions(uid, sessions)      → void
//   async getResource(uid, name)          → value | null  (name: 'credentials'|'folders'|...)
//   async setResource(uid, name, value)   → void
//   async deleteResource(uid, name)       → void
//   async deleteUserData(uid)             → void  (removes all files for uid)

import { existsSync, mkdirSync, rmSync } from 'fs';
import {
  loadUsers,
  withUsersLock,
  readEncryptedFile,
  writeEncryptedFile,
  userVaultDir,
  userVaultFile,
  userInfo,
} from './fileCrypto.js';
import {
  loadSessions as _loadSessions,
  saveSessions as _saveSessions,
} from './session.js';

export class FileVaultRepository {
  constructor(dataDir) {
    this._dataDir = dataDir;
  }

  // Atomic read-modify-write on the users array.
  // fn(users) mutates in place; return false to skip save.
  async withUserTransaction(fn) {
    return withUsersLock(fn);
  }

  async findUserByEmailHash(emailHash) {
    const users = loadUsers();
    return users.find(u => u.emailHash === emailHash) ?? null;
  }

  async findUserById(id) {
    const users = loadUsers();
    return users.find(u => u.id === id) ?? null;
  }

  async insertUser(user) {
    return this.withUserTransaction((users) => {
      if (users.some(u => u.emailHash === user.emailHash)) {
        const e = new Error('user exists'); e.code = 'USER_EXISTS'; throw e;
      }
      users.push(user);
      return user.id;
    });
  }

  // fn(user) mutates the matched user in place; helper returns fn's return value,
  // or null if no user matched (no write performed).
  async updateUserById(id, fn) {
    let ret = null, matched = false;
    await this.withUserTransaction((users) => {
      const u = users.find(x => x.id === id);
      if (!u) return false;            // skip save
      matched = true;
      ret = fn(u);
    });
    return matched ? ret : null;
  }

  async deleteUserById(id) {
    await this.withUserTransaction((users) => {
      const i = users.findIndex(u => u.id === id);
      if (i === -1) return false;
      users.splice(i, 1);
    });
  }

  async loadSessions(uid) {
    return _loadSessions(uid);
  }

  async saveSessions(uid, sessions) {
    _saveSessions(uid, sessions);
  }

  async getResource(uid, name) {
    const fp = userVaultFile(uid, name);
    const info = userInfo(uid, name);
    return readEncryptedFile(fp, info, null);
  }

  async setResource(uid, name, value) {
    const dir = userVaultDir(uid);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
    const fp = userVaultFile(uid, name);
    const info = userInfo(uid, name);
    writeEncryptedFile(fp, info, value);
  }

  async deleteResource(uid, name) {
    const fp = userVaultFile(uid, name);
    if (existsSync(fp)) rmSync(fp);
  }

  async deleteUserData(uid) {
    const dir = userVaultDir(uid);
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  }
}
