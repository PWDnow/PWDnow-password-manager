import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync, renameSync } from 'fs';
import { randomBytes, timingSafeEqual } from 'crypto';
import { lock } from 'proper-lockfile';
import path from 'path';

import { ctx } from '../lib/context.js';
import {
  readEncryptedFile,
  writeEncryptedFile,
  userVaultDir,
  userVaultFile,
  userInfo,
  userSharesDir,
  loadUsers,
  withUsersLock,
  withUserDirLock,
} from '../lib/fileCrypto.js';
import {
  authMiddleware,
  requireAuth,
  clearSessionCookies,
  getClientIp,
  generateUUID,
} from '../lib/session.js';
import { requireCsrf } from '../lib/csrf.js';
import {
  appendAuditEvent,
  compactIpInfo,
  loadAuditLog,
  saveAuditLog,
} from '../lib/audit.js';
import {
  resetAccountFailures,
  checkEmergencyRate,
} from '../lib/rateLimiter.js';
import {
  readUserBlob,
  readUserBlobAsync,
  writeUserBlob,
  writeUserBlobAsync,
  isMfaLocked,
  recordMfaFailure,
  clearMfaFailure,
  verifyPassword,
  secureOverwriteDir,
  performServerWipe,
} from './authRoutes.js';

// ── withEmergencyRequestsLock ─────────────────────────────────────────────────
// Same pattern as withUsersLock / withMfaPendingLock.
// H-10 fix: serialise the read-push-write on the per-user emergency_requests file.
async function withEmergencyRequestsLock(uid, fn) {
  const filePath = userVaultFile(uid, 'emergency_requests');
  const info = userInfo(uid, 'emergency_requests');
  // Ensure parent directory exists before proper-lockfile tries to lock the file.
  try { mkdirSync(userVaultDir(uid), { recursive: true, mode: 0o700 }); } catch (_) {}
  if (!existsSync(filePath)) {
    writeEncryptedFile(filePath, info, []);
  }
  let release = null;
  try {
    release = await lock(filePath, { retries: { retries: 20, minTimeout: 50, maxTimeout: 500 } });
    const requests = readEncryptedFile(filePath, info, []);
    const result = await fn(requests);
    if (result !== false) {
      writeEncryptedFile(filePath, info, requests);
    }
    return result;
  } finally {
    if (release) { try { await release(); } catch (_) {} }
  }
}

// ── Route mounter ─────────────────────────────────────────────────────────────

export function mountVaultRoutes(app) {

  // ── Vault CRUD ──────────────────────────────────────────────────────────────

  app.get('/api/vault/credentials', authMiddleware, requireAuth, async (req, res) => {
    res.json(await readUserBlobAsync(req.user.id, 'credentials', []));
  });
  app.put('/api/vault/credentials', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    await writeUserBlobAsync(req.user.id, 'credentials', req.body);
    res.json({ ok: true });
  });

  app.get('/api/vault/folders', authMiddleware, requireAuth, async (req, res) => {
    res.json(await readUserBlobAsync(req.user.id, 'folders', []));
  });
  app.put('/api/vault/folders', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    await writeUserBlobAsync(req.user.id, 'folders', req.body);
    res.json({ ok: true });
  });

  app.get('/api/vault/asset-holder', authMiddleware, requireAuth, async (req, res) => {
    res.json(await readUserBlobAsync(req.user.id, 'asset_holder', { emails: [], phoneNumbers: [], u2fKeys: [] }));
  });
  app.put('/api/vault/asset-holder', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    await writeUserBlobAsync(req.user.id, 'asset_holder', req.body);
    res.json({ ok: true });
  });

  // Travel Mode hidden-vault mirror. The body is opaque ciphertext from the
  // client (AES-GCM encrypted with the user's travel password — the server
  // cannot read it). We store/return it as a generic blob so the hidden data
  // survives browser-storage clears.
  app.get('/api/vault/travel-vault', authMiddleware, requireAuth, async (req, res) => {
    res.json(await readUserBlobAsync(req.user.id, 'travel_vault', { data: null }));
  });
  app.put('/api/vault/travel-vault', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    if (req.body.data.length > 5 * 1024 * 1024) return res.status(413).json({ error: 'payload_too_large' });
    await writeUserBlobAsync(req.user.id, 'travel_vault', req.body);
    res.json({ ok: true });
  });
  app.delete('/api/vault/travel-vault', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    try { await writeUserBlobAsync(req.user.id, 'travel_vault', { data: null }); } catch {}
    res.json({ ok: true });
  });

  // Travel Mode config (active flag, passwordHash, hiddenFolderIds, salt,
  // ivHex, kdf_version). Stored as a generic blob alongside travel-vault so the
  // entire Travel Mode state lives on the server in server-session mode.
  app.get('/api/vault/travel-config', authMiddleware, requireAuth, async (req, res) => {
    res.json(await readUserBlobAsync(req.user.id, 'travel_config', { data: null }));
  });
  app.put('/api/vault/travel-config', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    if (req.body.data.length > 64 * 1024) return res.status(413).json({ error: 'payload_too_large' });
    await writeUserBlobAsync(req.user.id, 'travel_config', req.body);
    res.json({ ok: true });
  });
  app.delete('/api/vault/travel-config', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    try { await writeUserBlobAsync(req.user.id, 'travel_config', { data: null }); } catch {}
    res.json({ ok: true });
  });

  // Duress Mode config mirror. Stored as a generic blob so the entire Duress
  // Mode state lives on the server in server-session mode — surviving logout,
  // "Clear site data", and new-device logins.
  app.get('/api/vault/duress-config', authMiddleware, requireAuth, async (req, res) => {
    res.json(await readUserBlobAsync(req.user.id, 'duress_config', { data: null }));
  });
  app.put('/api/vault/duress-config', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    if (req.body.data.length > 64 * 1024) return res.status(413).json({ error: 'payload_too_large' });
    await writeUserBlobAsync(req.user.id, 'duress_config', req.body);
    res.json({ ok: true });
  });
  app.delete('/api/vault/duress-config', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    try { await writeUserBlobAsync(req.user.id, 'duress_config', { data: null }); } catch {}
    res.json({ ok: true });
  });

  // Server-authoritative duress enforcement. The encrypted /api/vault/duress-config
  // above is the full client-side config — the server cannot read it. This endpoint
  // stores a separate PLAINTEXT flag so the server can enforce the duress counter
  // during /api/auth/login (before authentication). Mirrors how `mfaEnforce` works.
  app.put('/api/vault/duress-enforce', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { armed, maxAttempts } = req.body || {};
    if (typeof armed !== 'boolean') return res.status(400).json({ error: 'invalid_input' });
    const max = Math.max(1, Math.min(20, Number(maxAttempts) || 3));
    let emailHash = null;
    const found = await withUsersLock(async (users) => {
      const idx = users.findIndex(x => x.id === req.user.id);
      if (idx === -1) return false;
      users[idx].duressEnforce = armed ? { armed: true, maxAttempts: max } : null;
      users[idx].duressFailureCount = 0;
      emailHash = users[idx].emailHash;
    });
    if (found === false) return res.status(401).json({ error: 'user_not_found' });
    // Clear the in-memory account-lockout counter for this account so any
    // failures accumulated before arming don't strand the wipe path behind an
    // 'account_locked' response.
    if (emailHash) resetAccountFailures(emailHash);
    res.json({ ok: true });
  });
  app.delete('/api/vault/duress-enforce', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const found = await withUsersLock(async (users) => {
      const idx = users.findIndex(x => x.id === req.user.id);
      if (idx === -1) return false;
      users[idx].duressEnforce = null;
      users[idx].duressFailureCount = 0;
    });
    if (found === false) return res.status(401).json({ error: 'user_not_found' });
    res.json({ ok: true });
  });

  app.get('/api/vault/profile', authMiddleware, requireAuth, async (req, res) => {
    res.json(await readUserBlobAsync(req.user.id, 'profile', { firstName: '', lastName: '', email: '' }));
  });
  app.put('/api/vault/profile', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') return res.status(400).json({ error: 'invalid_input' });
    await writeUserBlobAsync(req.user.id, 'profile', req.body);
    res.json({ ok: true });
  });

  app.get('/api/vault/mfa', authMiddleware, requireAuth, async (req, res) => {
    res.json(await readUserBlobAsync(req.user.id, 'mfa_config', {
      totp: { enabled: false },
      webauthn: { enabled: false, credentials: [] },
      passkey:  { enabled: false, credentials: [] },
      platform: { enabled: false, credentials: [] },
      email:    { enabled: false },
      passwordlessEnabled: false,
    }));
  });
  app.put('/api/vault/mfa', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    if (!req.body || typeof req.body.data !== 'string') {
      return res.status(400).json({ error: 'invalid_input' });
    }
    writeUserBlob(req.user.id, 'mfa_config', req.body);

    // H-3 fix: lock users.enc — concurrent PUT /api/vault/mfa calls would
    // otherwise clobber the TOTP secret or enforce flags.
    const { enforce, serverSecret } = req.body;
    await withUsersLock(async (users) => {
      const idx = users.findIndex(x => x.id === req.user.id);
      if (idx === -1) return false;
      if (enforce && typeof enforce === 'object') {
        users[idx].mfaEnforce = {
          totp:  enforce.totp  === true,
          email: enforce.email === true,
        };
      }
      // TOTP secret stored server-encrypted so /login/finish can verify codes
      // without the client session key (which doesn't exist at login time).
      if (typeof serverSecret === 'string' && serverSecret.length > 0) {
        users[idx].mfaTotpSecret = serverSecret;
      } else if (enforce && enforce.totp === false) {
        users[idx].mfaTotpSecret = null; // TOTP disabled — purge the server-held secret
      }
    });

    appendAuditEvent(req.user.id, { action: 'mfa_changed', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true });
  });

  // ── SMTP config persistence (server-side, needed for login OTP sending) ──────
  app.get('/api/vault/smtp-config', authMiddleware, requireAuth, async (req, res) => {
    const cfg = readUserBlob(req.user.id, 'smtp_config', null);
    if (!cfg) return res.json(null);
    // Never return the password to the browser — it was stored here for server use only.
    const { password: _pw, ...safe } = cfg;
    res.json({ ...safe, passwordSet: !!_pw });
  });

  app.put('/api/vault/smtp-config', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const { host, port, protocol, username, password, fromName, fromAddress, mxVerified } = req.body ?? {};
    if (!host || typeof host !== 'string' || !port || !username || typeof username !== 'string') {
      return res.status(400).json({ error: 'invalid_input' });
    }
    const BLOCKED_HOST_RE = /^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1|169\.254\.|fd[0-9a-f]{2}:|fc00:)/i;
    if (BLOCKED_HOST_RE.test(String(host).trim())) {
      return res.status(400).json({ error: 'invalid_smtp_host' });
    }
    writeUserBlob(req.user.id, 'smtp_config', { host, port, protocol, username, password: password || '', fromName, fromAddress, mxVerified });
    res.json({ ok: true });
  });

  app.delete('/api/vault/smtp-config', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    writeUserBlob(req.user.id, 'smtp_config', null);
    res.json({ ok: true });
  });

  // ── Secure Sharing ────────────────────────────────────────────────────────────
  // Encrypted blobs stored per-user at vault/<uid>/shares/<id>.json.
  // The share key lives only in the URL fragment — the server never sees it.

  const SHARE_TTL_MS = {
    '1h':  1 * 3600_000,
    '24h': 24 * 3600_000,
    '7d':  7 * 24 * 3600_000,
  };

  app.post('/api/vault/shares', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const { encryptedBlob, iv, ttl, singleView, label } = req.body ?? {};
    if (!encryptedBlob || typeof encryptedBlob !== 'string') return res.status(400).json({ error: 'missing_blob' });
    if (!iv || typeof iv !== 'string') return res.status(400).json({ error: 'missing_iv' });
    const ttlMs = SHARE_TTL_MS[ttl] ?? SHARE_TTL_MS['24h'];
    const uid = req.user.id;
    const sharesDir = userSharesDir(uid);
    if (!existsSync(sharesDir)) mkdirSync(sharesDir, { recursive: true, mode: 0o700 });

    const shareId = randomBytes(16).toString('hex');
    const record = {
      id: shareId,
      label: typeof label === 'string' ? label.slice(0, 100) : '',
      encryptedBlob,
      iv,
      createdAt: Date.now(),
      expiresAt: Date.now() + ttlMs,
      singleView: Boolean(singleView),
      viewed: false,
    };
    const sharePath = path.join(sharesDir, `${shareId}.json`);
    writeFileSync(sharePath, JSON.stringify(record), { mode: 0o600 });
    appendAuditEvent(uid, { action: 'share_created', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, resourceLabel: record.label, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true, shareId });
  });

  app.get('/api/vault/shares', authMiddleware, requireAuth, (req, res) => {
    const sharesDir = userSharesDir(req.user.id);
    if (!existsSync(sharesDir)) return res.json({ ok: true, shares: [] });
    const shares = readdirSync(sharesDir)
      .filter(f => f.endsWith('.json'))
      .map(f => {
        try { return JSON.parse(readFileSync(path.join(sharesDir, f), 'utf8')); } catch { return null; }
      })
      .filter(Boolean)
      .map(({ id, createdAt, expiresAt, singleView, viewed, label }) => ({ id, createdAt, expiresAt, singleView, viewed, label: label || '' }));
    res.json({ ok: true, shares });
  });

  app.delete('/api/vault/shares/:shareId', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const shareId = req.params.shareId;
    if (!/^[0-9a-f]{32}$/.test(shareId)) return res.status(400).json({ error: 'invalid_id' });
    const sharePath = path.join(userSharesDir(req.user.id), `${shareId}.json`);
    let label = '';
    if (existsSync(sharePath)) {
      try { label = JSON.parse(readFileSync(sharePath, 'utf8')).label || ''; } catch { /* ignore */ }
      rmSync(sharePath);
    }
    appendAuditEvent(req.user.id, { action: 'share_revoked', ip: getClientIp(req), ipInfo: compactIpInfo(req.ipRecord), userAgent: req.headers['user-agent'] || '', success: true, resourceLabel: label, riskFlags: req.ipRecord?.riskFlags ?? [] });
    res.json({ ok: true });
  });

  // Public endpoint — no auth. Rate limited to prevent filesystem enumeration.
  app.get('/api/share/:shareId', async (req, res) => {
    if (!checkEmergencyRate(getClientIp(req))) {
      return res.status(429).json({ error: 'too_many_requests' });
    }
    const { shareId } = req.params;
    if (!/^[0-9a-f]{32}$/.test(shareId)) return res.status(400).json({ error: 'invalid_id' });

    // O(users) scan — acceptable for self-hosted scale.
    const vaultDir = path.join(ctx.DATA_DIR, 'vault');
    if (!existsSync(vaultDir)) return res.status(404).json({ error: 'not_found' });

    let recordPath = null;
    for (const uid of readdirSync(vaultDir)) {
      const p = path.join(vaultDir, uid, 'shares', `${shareId}.json`);
      if (existsSync(p)) {
        recordPath = p;
        break;
      }
    }
    if (!recordPath) return res.status(404).json({ error: 'not_found' });

    let release = null;
    let record = null;
    try {
      // Lock enforced to prevent race condition in single-view claim.
      release = await lock(recordPath, { retries: { retries: 10, minTimeout: 100 } });
      if (!existsSync(recordPath)) return res.status(404).json({ error: 'not_found' });
      try { record = JSON.parse(readFileSync(recordPath, 'utf8')); } catch { return res.status(500).json({ error: 'corrupt' }); }

      if (Date.now() > record.expiresAt) {
        try { rmSync(recordPath); } catch { /* ignore */ }
        return res.status(410).json({ error: 'expired' });
      }

      if (record.singleView) {
        if (record.viewed) {
          return res.status(410).json({ error: 'already_viewed' });
        }
        record.viewed = true;
        const tmp = recordPath + '.tmp';
        try {
          writeFileSync(tmp, JSON.stringify(record), { mode: 0o600 });
          renameSync(tmp, recordPath); // atomic rename
        } catch (e) {
          console.error('[share] Atomic update failed:', e.message);
          return res.status(500).json({ error: 'server_error' });
        }
      }
    } finally {
      if (release) await release().catch(() => {});
    }

    res.json({ ok: true, encryptedBlob: record.encryptedBlob, iv: record.iv, expiresAt: record.expiresAt, singleView: record.singleView });
  });

  // ── Emergency Access ─────────────────────────────────────────────────────────
  // Config stored per-user at vault/<uid>/emergency.enc; the token in the config
  // is the public URL token (32 hex bytes).

  function emergencyPath(uid) { return userVaultFile(uid, 'emergency'); }
  function emergencyInfo(uid) { return userInfo(uid, 'emergency'); }
  function emergencyRequestsPath(uid) { return userVaultFile(uid, 'emergency_requests'); }
  function emergencyRequestsInfo(uid) { return userInfo(uid, 'emergency_requests'); }

  app.get('/api/vault/emergency', authMiddleware, requireAuth, (req, res) => {
    const cfg = readEncryptedFile(emergencyPath(req.user.id), emergencyInfo(req.user.id), null);
    res.json({ ok: true, config: cfg });
  });

  app.post('/api/vault/emergency', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { contactEmail, waitPeriodHours, password } = req.body || {};
    // #5-FIX: require password re-verification before writing a recovery backdoor (CWE-620).
    if (typeof password !== 'string') return res.status(400).json({ error: 'password_required' });
    if (!contactEmail || typeof contactEmail !== 'string') return res.status(400).json({ error: 'invalid_email' });
    const hours = Number(waitPeriodHours);
    if (![24, 48, 72, 168].includes(hours)) return res.status(400).json({ error: 'invalid_wait_period' });

    const users = loadUsers();
    const u = users.find(x => x.id === req.user.id);
    if (!u) return res.status(401).json({ error: 'user_not_found' });
    if (isMfaLocked(u.id)) return res.status(429).json({ ok: false, error: 'too_many_attempts' });
    const verified = await verifyPassword(u.passwordHash, password, u.salt);
    if (!verified) {
      recordMfaFailure(u.id);
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    clearMfaFailure(u.id);

    const uid = req.user.id;
    if (!existsSync(userVaultDir(uid))) mkdirSync(userVaultDir(uid), { recursive: true, mode: 0o700 });
    const cfg = {
      enabled: true,
      contactEmail: contactEmail.trim().toLowerCase(),
      waitPeriodHours: hours,
      token: randomBytes(32).toString('hex'),
      createdAt: Date.now(),
    };
    writeEncryptedFile(emergencyPath(uid), emergencyInfo(uid), cfg);
    // Never return the token in the creation response — prevents log exposure.
    // The authenticated owner can retrieve it via GET /api/vault/emergency.
    const { token: _stripped, ...safeConfig } = cfg;
    res.json({ ok: true, config: safeConfig });
  });

  app.delete('/api/vault/emergency', authMiddleware, requireAuth, requireCsrf, (req, res) => {
    const p = emergencyPath(req.user.id);
    if (existsSync(p)) rmSync(p);
    res.json({ ok: true });
  });

  // Public endpoint — no auth. Rate limited: each call iterates all users + decrypts
  // emergency files, so without limiting this enables cross-tenant DoS.
  app.post('/api/emergency/request/:token', async (req, res) => {
    if (!checkEmergencyRate(getClientIp(req))) {
      return res.status(429).json({ error: 'too_many_requests' });
    }
    const { token } = req.params;
    const { requesterName, requesterEmail } = req.body ?? {};
    if (!token || !/^[0-9a-f]{64}$/.test(token)) return res.status(400).json({ error: 'invalid_token' });
    if (!requesterName || typeof requesterName !== 'string') return res.status(400).json({ error: 'invalid_name' });
    if (requesterEmail !== undefined && requesterEmail !== null && requesterEmail !== '') {
      if (typeof requesterEmail !== 'string' || requesterEmail.length > 320 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(requesterEmail)) {
        return res.status(400).json({ error: 'invalid_email' });
      }
    }

    const users = loadUsers();
    let owner = null;
    let ownerCfg = null;
    for (const u of users) {
      const cfg = readEncryptedFile(emergencyPath(u.id), emergencyInfo(u.id), null);
      // Constant-time comparison prevents timing oracle on token prefix.
      const tokenMatch = cfg && cfg.enabled && cfg.token && token &&
        cfg.token.length === token.length &&
        timingSafeEqual(Buffer.from(cfg.token, 'hex'), Buffer.from(token, 'hex'));
      if (tokenMatch) {
        owner = u;
        ownerCfg = cfg;
        break;
      }
    }
    if (!owner) return res.status(404).json({ error: 'not_found' });

    // H-10 fix: serialise the read-push-write on the per-user emergency_requests file.
    await withEmergencyRequestsLock(owner.id, async (requests) => {
      requests.push({
        id: generateUUID(),
        requesterName: requesterName.trim().slice(0, 100),
        requesterEmail: (requesterEmail ?? '').trim().toLowerCase().slice(0, 200),
        requestedAt: Date.now(),
        status: 'pending',
        grantExpiresAt: Date.now() + ownerCfg.waitPeriodHours * 3600_000,
      });
    });
    res.json({ ok: true, waitPeriodHours: ownerCfg.waitPeriodHours });
  });

  app.get('/api/vault/emergency/requests', authMiddleware, requireAuth, (req, res) => {
    const requests = readEncryptedFile(emergencyRequestsPath(req.user.id), emergencyRequestsInfo(req.user.id), []);
    res.json({ ok: true, requests });
  });

  app.post('/api/vault/emergency/respond', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { requestId, action } = req.body ?? {};
    if (!requestId || !['grant', 'deny'].includes(action)) return res.status(400).json({ error: 'invalid_params' });
    const uid = req.user.id;
    // H-10 fix: same lock as the request-append path so grant/deny don't race
    // a concurrent append (which would otherwise resurrect a denied request
    // by clobbering the writer that flipped the status).
    let notFound = false;
    await withEmergencyRequestsLock(uid, async (requests) => {
      const idx = requests.findIndex(r => r.id === requestId);
      if (idx === -1) { notFound = true; return false; }
      requests[idx].status = action === 'grant' ? 'granted' : 'denied';
      requests[idx].respondedAt = Date.now();
    });
    if (notFound) return res.status(404).json({ error: 'not_found' });
    res.json({ ok: true });
  });

  // ── Account wipe ──────────────────────────────────────────────────────────────
  app.post('/api/vault/wipe', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    // #1-FIX: require password re-verification before destructive wipe (CWE-306).
    const { password } = req.body ?? {};
    if (typeof password !== 'string') return res.status(400).json({ error: 'password_required' });
    const users = loadUsers();
    const u = users.find(x => x.id === req.user.id);
    if (!u) return res.status(401).json({ error: 'user_not_found' });
    if (isMfaLocked(u.id)) return res.status(429).json({ ok: false, error: 'too_many_attempts' });
    const verified = await verifyPassword(u.passwordHash, password, u.salt);
    if (!verified) {
      recordMfaFailure(u.id);
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    clearMfaFailure(u.id);

    await performServerWipe(req.user.id);
    clearSessionCookies(req, res);
    res.json({ ok: true });
  });

  // ── Audit Log ─────────────────────────────────────────────────────────────────
  app.get('/api/audit/events', authMiddleware, requireAuth, (req, res) => {
    const limit  = Math.min(Number(req.query.limit)  || 50, 200);
    const offset = Math.max(Number(req.query.offset) || 0,  0);
    const action = req.query.action || null;
    const since  = Number(req.query.since) || 0;
    let events = loadAuditLog(req.user.id);
    if (action) events = events.filter(e => e.action === action);
    if (since)  events = events.filter(e => e.ts >= since);
    events = events.slice().reverse(); // newest first
    res.json({ ok: true, events: events.slice(offset, offset + limit), total: events.length });
  });

  app.delete('/api/audit/events', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    // Require password re-verification with brute-force lockout before clearing logs.
    const { password } = req.body ?? {};
    if (typeof password !== 'string') {
      return res.status(400).json({ error: 'password_required' });
    }
    const users = loadUsers();
    const u = users.find(x => x.id === req.user.id);
    if (!u) return res.status(401).json({ error: 'user_not_found' });

    if (isMfaLocked(u.id)) {
      return res.status(429).json({ ok: false, error: 'too_many_attempts' });
    }

    const verified = await verifyPassword(u.passwordHash, password, u.salt);
    if (!verified) {
      recordMfaFailure(u.id);
      appendAuditEvent(req.user.id, { action: 'audit_clear_rejected', ip: getClientIp(req), success: false });
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    clearMfaFailure(u.id);

    let release = null;
    try {
      const dir = userVaultDir(req.user.id);
      if (existsSync(dir)) {
        release = await lock(dir, { retries: { retries: 10, minTimeout: 100 } });
      }
      // Write a permanent marker before clearing so the next session can detect the gap.
      const marker = { id: generateUUID(), ts: Date.now(), action: 'audit_cleared', ip: getClientIp(req), success: true };
      saveAuditLog(req.user.id, [marker]);
    } finally {
      if (release) await release().catch(() => {});
    }
    res.json({ ok: true });
  });

  // ── Expiry notification ───────────────────────────────────────────────────────
  // SMTP config is provided by the client (stored client-side in encrypted localStorage)
  // so no SMTP credentials are stored on the server.
  app.post('/api/send-expiry-notification', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { smtp, credentials: expiredCreds, toEmail } = req.body ?? {};
    if (
      !smtp?.host || !smtp?.port || !smtp?.username || !smtp?.password ||
      !Array.isArray(expiredCreds) || !toEmail || typeof toEmail !== 'string' ||
      toEmail.length > 320
    ) {
      return res.status(400).json({ error: 'invalid_input' });
    }
    if (expiredCreds.length === 0) return res.json({ ok: true, sent: 0 });

    // Block SSRF to RFC-1918, loopback, and metadata endpoints.
    const smtpHost = String(smtp.host).trim().toLowerCase();
    const BLOCKED_HOST_RE = /^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1|169\.254\.|fd[0-9a-f]{2}:|fc00:)/i;
    if (BLOCKED_HOST_RE.test(smtpHost)) {
      return res.status(400).json({ error: 'invalid_smtp_host' });
    }

    const { default: nodemailer } = await import('nodemailer');
    const secure = smtp.protocol === 'ssl_tls';
    const transport = nodemailer.createTransport({
      host: smtpHost,
      port: Number(smtp.port),
      secure,
      auth: { user: String(smtp.username), pass: String(smtp.password) },
    });

    const list = expiredCreds
      .filter(c => c && typeof c.service === 'string')
      .map(c => `• ${c.service} (every ${c.value} ${c.unit})`)
      .join('\n');

    try {
      // `from` is always the authenticated SMTP username — never attacker-controlled.
      await transport.sendMail({
        from: String(smtp.username),
        to: toEmail,
        subject: 'PWDnow — Password Expiry Alert',
        text: `The following credentials in your vault have expired:\n\n${list}\n\nPlease update them at your earliest convenience.`,
      });
      res.json({ ok: true, sent: expiredCreds.length });
    } catch (err) {
      console.error('[expiry-notify]', err.message);
      res.status(502).json({ error: 'smtp_error' });
    }
  });
}
