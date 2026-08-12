/** @vitest-environment jsdom */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  enableTravelMode, disableTravelMode,
  armDuressMode, disarmDuressMode, checkIsDuressPassword,
  getTravelModeConfig, getTravelModeConfigAsync,
  getDuressModeConfig, getDuressModeConfigFull,
} from './securityModes';
import { writeEncryptedLocal } from './localCrypto';
import { keyStore, deriveLocalKeys } from '../crypto/keystore';

describe('Security Modes (Travel & Duress) - Argon2id', () => {
  const password = 'RealPassword123!';
  const salt = '0123456789abcdef0123456789abcdef';
  const token = 'session-token-abc';

  beforeEach(async () => {
    localStorage.clear();
    keyStore.clear();
    const { v1, v2 } = await deriveLocalKeys(password, salt, token);
    keyStore.storeLocalKey(v1.encKey, 1);
    keyStore.storeSigningKey(v1.sigKey, 1);
    if (v2) {
      keyStore.storeLocalKey(v2.encKey, 2);
      keyStore.storeSigningKey(v2.sigKey, 2);
      const saltBytes = Uint8Array.from(salt.match(/../g)!.map(h => parseInt(h, 16)));
      keyStore.setV2Salt(saltBytes);
    }
  }, 60000);

  describe('Travel Mode', () => {
    it('should enable travel mode with v2 KDF', async () => {
      const travelPass = 'TravelPass123!';
      const hiddenFolders = ['f1'];
      const creds = [{ id: 'c1', folderId: 'f1' }, { id: 'c2', folderId: 'f2' }];
      const folders = [{ id: 'f1' }, { id: 'f2' }];

      await enableTravelMode(travelPass, hiddenFolders, creds, folders);

      const cfg = await getTravelModeConfigAsync();
      expect(cfg.active).toBe(true);
      expect(cfg.kdf_version).toBe(2);
      
      const stored = localStorage.getItem('_cache_local_xvc');
      expect(stored).toContain('"iv"');
      expect(stored).toContain('"ct"');
    }, 60000);

    it('should disable travel mode and re-merge data', async () => {
      const travelPass = 'TravelPass123!';
      const hiddenFolders = ['f1'];
      const creds = [{ id: 'c1', folderId: 'f1' }, { id: 'c2', folderId: 'f2' }];
      const folders = [{ id: 'f1' }, { id: 'f2' }];

      await enableTravelMode(travelPass, hiddenFolders, creds, folders);

      const result = await disableTravelMode(travelPass, [{ id: 'c2', folderId: 'f2' }], [{ id: 'f2' }]);
      expect(result.ok).toBe(true);
      expect(result.credentials).toHaveLength(2);
      expect(result.folders).toHaveLength(2);

      const cfg = await getTravelModeConfigAsync();
      expect(cfg.active).toBe(false);
    }, 60000);

    // Regression: sync getter must report the real state — it was previously a
    // stub that always returned active:false, leaving the Settings UI stuck on
    // "Inactive" right after activation, and the VaultContext filter dead.
    it('sync getTravelModeConfig reflects state after enable', async () => {
      const travelPass = 'TravelPass123!';
      await enableTravelMode(travelPass, ['f1'],
        [{ id: 'c1', folderId: 'f1' }, { id: 'c2', folderId: 'f2' }],
        [{ id: 'f1' }, { id: 'f2' }]);

      const cfg = getTravelModeConfig();
      expect(cfg.active).toBe(true);
      expect(cfg.hiddenFolderIds).toEqual(['f1']);
    }, 60000);

    // Regression: config must survive a simulated logout/login. Previously the
    // config was written via the v2 (Argon2id) key bound to the per-session
    // token. After logout the v2 key was rotated, leaving _tm_cfg permanently
    // undecryptable and silently downgrading state to active:false.
    it('travel config survives session-key rotation (logout/login)', async () => {
      const travelPass = 'TravelPass123!';
      await enableTravelMode(travelPass, ['f1'],
        [{ id: 'c1', folderId: 'f1' }, { id: 'c2', folderId: 'f2' }],
        [{ id: 'f1' }, { id: 'f2' }]);

      // Simulate logout: drop in-memory keys but keep localStorage (browser
      // restart between sessions).
      keyStore.clear();
      // Simulate re-login with the same password — same v1 key, NEW v2 token.
      const { v1, v2 } = await deriveLocalKeys(password, salt, 'different-token-xyz');
      keyStore.storeLocalKey(v1.encKey, 1);
      keyStore.storeSigningKey(v1.sigKey, 1);
      if (v2) {
        keyStore.storeLocalKey(v2.encKey, 2);
        keyStore.storeSigningKey(v2.sigKey, 2);
        const saltBytes = Uint8Array.from(salt.match(/../g)!.map(h => parseInt(h, 16)));
        keyStore.setV2Salt(saltBytes);
      }

      const sync = getTravelModeConfig();
      expect(sync.active).toBe(true);
      expect(sync.hiddenFolderIds).toEqual(['f1']);
    }, 60000);

    // Regression: a legacy config previously written via writeEncryptedLocal
    // (v2-bound) must migrate transparently when the async getter is called.
    it('migrates legacy encrypted _tm_cfg to plaintext on async read', async () => {
      const legacyCfg = {
        active: true, passwordHash: 'deadbeef', hiddenFolderIds: ['legacy-f1'],
        salt: 'legacy-salt', ivHex: 'cafe', kdf_version: 2 as const,
      };
      // Write via the legacy path (v2 encrypted) under the same key.
      await writeEncryptedLocal('_tm_cfg', JSON.stringify(legacyCfg));
      // Drop the plaintext to force the async migration branch.
      const raw = localStorage.getItem('_tm_cfg');
      expect(raw).toBeTruthy();
      // The v2 envelope starts with the v2 prefix, not '{', so sync returns default.
      expect(getTravelModeConfig().active).toBe(false);

      const migrated = await getTravelModeConfigAsync();
      expect(migrated.active).toBe(true);
      expect(migrated.hiddenFolderIds).toEqual(['legacy-f1']);
      // After migration, sync read must work too.
      expect(getTravelModeConfig().active).toBe(true);
    }, 60000);

    // Regression: the exact scenario the user reported — logout, clear
    // cookies AND cache (localStorage), then log in. Server-side mirror must
    // rehydrate localStorage so the UI shows Active and the Disable button.
    it('clear-cache-then-login: async hydrates _tm_cfg from server', async () => {
      // Pre-state: a server has the user's travel config from a prior session.
      const serverCfg = {
        active: true, passwordHash: 'serverhash', hiddenFolderIds: ['srv-f1', 'srv-f2'],
        salt: 'srv-salt', ivHex: 'feed', kdf_version: 2 as const,
      };

      // Simulate "Clear site data": localStorage is empty.
      localStorage.clear();
      expect(getTravelModeConfig().active).toBe(false); // sync sees nothing

      // Simulate fresh server-session cookie (set after the user logs back in).
      Object.defineProperty(document, 'cookie', {
        writable: true, configurable: true,
        value: '_pwd_csrf=fresh-csrf-token',
      });

      // Mock the server response for the new endpoint.
      const fetchMock = vi.fn(async (url: string) => {
        if (typeof url === 'string' && url.endsWith('/api/vault/travel-config')) {
          return {
            ok: true,
            json: async () => ({ data: JSON.stringify(serverCfg) }),
          } as Response;
        }
        return { ok: false, json: async () => null } as Response;
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = fetchMock as any;

      try {
        const hydrated = await getTravelModeConfigAsync();
        expect(hydrated.active).toBe(true);
        expect(hydrated.hiddenFolderIds).toEqual(['srv-f1', 'srv-f2']);
        // localStorage cache must be repopulated so subsequent sync reads work
        // (this is what VaultContext's filter and Settings.tsx initial state
        // depend on for non-async callers).
        const cached = getTravelModeConfig();
        expect(cached.active).toBe(true);
        expect(cached.hiddenFolderIds).toEqual(['srv-f1', 'srv-f2']);
        expect(fetchMock).toHaveBeenCalledWith(
          '/api/vault/travel-config',
          expect.objectContaining({ credentials: 'same-origin' }),
        );
      } finally {
        globalThis.fetch = originalFetch;
        Object.defineProperty(document, 'cookie', {
          writable: true, configurable: true, value: '',
        });
      }
    }, 60000);

    // Regression: when the server explicitly returns no config (the user
    // disabled Travel Mode from another device, or never enabled it), the
    // sync cache must NOT lie. Stale localStorage from an unrelated user on
    // the same device would otherwise mis-show "Active".
    it('null server response clears stale localStorage cache', async () => {
      // Stale localStorage from a previous user/session.
      const staleCfg = {
        active: true, passwordHash: 'old', hiddenFolderIds: ['stale-f1'],
        salt: 'old', ivHex: 'aa', kdf_version: 2 as const,
      };
      localStorage.setItem('_tm_cfg', JSON.stringify(staleCfg));
      expect(getTravelModeConfig().active).toBe(true);

      Object.defineProperty(document, 'cookie', {
        writable: true, configurable: true, value: '_pwd_csrf=fresh',
      });

      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn(async () => ({
        ok: true, json: async () => ({ data: null }),
      } as Response)) as any;

      try {
        const result = await getTravelModeConfigAsync();
        expect(result.active).toBe(false);
        expect(getTravelModeConfig().active).toBe(false);
      } finally {
        globalThis.fetch = originalFetch;
        Object.defineProperty(document, 'cookie', {
          writable: true, configurable: true, value: '',
        });
      }
    }, 60000);
  });

  describe('Duress Mode', () => {
    it('should arm duress mode with Argon2id PHC hash', async () => {
      const duressPass = 'Duress123!';
      await armDuressMode(duressPass, 5);

      // Pre-login sentinel: armed=true but no hash exposed (CWE-312 fix).
      const sentinel = getDuressModeConfig();
      expect(sentinel.armed).toBe(true);
      expect(sentinel.passwordHash).toBeNull();

      // Full config (encrypted path in session, plaintext fallback in test env).
      const cfg = await getDuressModeConfigFull();
      expect(cfg.armed).toBe(true);
      expect(cfg.passwordHash).toContain('$argon2id$');
      // Verify upgraded params: m=262144 (256 MiB), t=3.
      expect(cfg.passwordHash).toContain('m=262144,t=3');
    }, 60000);

    it('should verify duress password correctly', async () => {
      const duressPass = 'Duress123!';
      await armDuressMode(duressPass, 5);

      const isDuress = await checkIsDuressPassword(duressPass);
      expect(isDuress).toBe(true);

      const isNotDuress = await checkIsDuressPassword('WrongPass');
      expect(isNotDuress).toBe(false);
    }, 120000);

    // Regression: user reported that after setting maxAttempts to 3, the
    // Settings dropdown reverted to 5 (the hardcoded fallback) after re-mount.
    // Sentinel must persist maxAttempts so the sync getter returns it.
    it('should persist maxAttempts in the sentinel (sync getter)', async () => {
      await armDuressMode('Duress123!', 3);
      const cfg = getDuressModeConfig();
      expect(cfg.armed).toBe(true);
      expect(cfg.maxAttempts).toBe(3);
      expect(cfg.attemptsRemaining).toBe(3);
      // Hash MUST NOT leak through the sync getter.
      expect(cfg.passwordHash).toBeNull();
    }, 60000);

    // Regression: user reported that after logging out and back in, Duress
    // Mode showed "Disarmed". The sentinel survives `keyStore.clear()` because
    // it is plaintext localStorage; the sync getter should still report armed.
    it('should survive logout (keyStore.clear) and remain armed', async () => {
      await armDuressMode('Duress123!', 3);
      // Simulate the logout: keys cleared, localStorage retained.
      keyStore.clear();

      const cfg = getDuressModeConfig();
      expect(cfg.armed).toBe(true);
      expect(cfg.maxAttempts).toBe(3);
    }, 60000);

    it('should mirror duress config to server when _pwd_csrf cookie is set', async () => {
      Object.defineProperty(document, 'cookie', {
        writable: true, configurable: true, value: '_pwd_csrf=test-csrf',
      });

      const fetchMock = vi.fn(async () => ({ ok: true, json: async () => ({ ok: true }) } as Response));
      const originalFetch = globalThis.fetch;
      globalThis.fetch = fetchMock as any;

      try {
        await armDuressMode('Duress123!', 4);
        const putCall = (fetchMock.mock.calls as any[]).find((c: any[]) => c[0] === '/api/vault/duress-config' && c[1]?.method === 'PUT');
        expect(putCall).toBeDefined();
        const body = JSON.parse(putCall[1].body);
        const parsed = JSON.parse(body.data);
        expect(parsed.armed).toBe(true);
        expect(parsed.maxAttempts).toBe(4);
        expect(parsed.passwordHash).toContain('$argon2id$');
      } finally {
        globalThis.fetch = originalFetch;
        Object.defineProperty(document, 'cookie', {
          writable: true, configurable: true, value: '',
        });
      }
    }, 60000);

    it('should hydrate from server mirror on getDuressModeConfigFull', async () => {
      // Local state empty (simulates new browser / post-clear-site-data).
      localStorage.clear();
      Object.defineProperty(document, 'cookie', {
        writable: true, configurable: true, value: '_pwd_csrf=test-csrf',
      });

      const serverCfg = {
        armed: true, passwordHash: '$argon2id$v=19$m=262144,t=3,p=1$abcd$efef',
        maxAttempts: 7, attemptsRemaining: 7, salt: 'abcd',
      };
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn(async (url: any) => {
        if (typeof url === 'string' && url === '/api/vault/duress-config') {
          return { ok: true, json: async () => ({ data: JSON.stringify(serverCfg) }) } as Response;
        }
        return { ok: false, json: async () => ({}) } as Response;
      }) as any;

      try {
        const cfg = await getDuressModeConfigFull();
        expect(cfg.armed).toBe(true);
        expect(cfg.maxAttempts).toBe(7);
        // Server hydration should refresh local cache for subsequent sync reads.
        const sync = getDuressModeConfig();
        expect(sync.armed).toBe(true);
        expect(sync.maxAttempts).toBe(7);
      } finally {
        globalThis.fetch = originalFetch;
        Object.defineProperty(document, 'cookie', {
          writable: true, configurable: true, value: '',
        });
      }
    }, 60000);

    it('should DELETE the server mirror on disarm', async () => {
      await armDuressMode('Duress123!', 3);
      Object.defineProperty(document, 'cookie', {
        writable: true, configurable: true, value: '_pwd_csrf=test-csrf',
      });

      const fetchMock = vi.fn(async () => ({ ok: true, json: async () => ({ ok: true }) } as Response));
      const originalFetch = globalThis.fetch;
      globalThis.fetch = fetchMock as any;

      try {
        await disarmDuressMode();
        const deleteCall = (fetchMock.mock.calls as any[]).find((c: any[]) => c[0] === '/api/vault/duress-config' && c[1]?.method === 'DELETE');
        expect(deleteCall).toBeDefined();
        // Local sentinel must be cleared too.
        expect(getDuressModeConfig().armed).toBe(false);
      } finally {
        globalThis.fetch = originalFetch;
        Object.defineProperty(document, 'cookie', {
          writable: true, configurable: true, value: '',
        });
      }
    }, 60000);

    // Regression: Login.tsx must call `recordFailedLoginAttempt` with `await`.
    // Calling it without await yields a Promise which is always truthy, making
    // the wipe branch fire on every wrong password (instead of after N).
    it('recordFailedLoginAttempt returns false until attemptsRemaining hits 0', async () => {
      const { recordFailedLoginAttempt } = await import('./securityModes');
      await armDuressMode('Duress123!', 3);

      // Attempts 1 & 2 must not trigger wipe.
      expect(await recordFailedLoginAttempt()).toBe(false);
      expect(getDuressModeConfig().attemptsRemaining).toBe(2);
      expect(await recordFailedLoginAttempt()).toBe(false);
      expect(getDuressModeConfig().attemptsRemaining).toBe(1);

      // Third (exhausting) attempt returns true.
      expect(await recordFailedLoginAttempt()).toBe(true);
      expect(getDuressModeConfig().attemptsRemaining).toBe(0);
    }, 120000);

    // Regression for the writeEncryptedLocal/DURESS_KEY clobber bug.
    // armDuressMode writes plaintext to DURESS_KEY then writeEncryptedLocal
    // overwrites the same key with the encrypted v2 token. Pre-login the
    // session key isn't in memory, so getDuressModeConfigFull's plaintext
    // fallback can't read its own encrypted output and falls to defaults.
    // Result: recordFailedLoginAttempt returns false on every call - wipe
    // never fires. Simulate the pre-login state by clearing the keyStore
    // AFTER arming (the same thing that happens at the login page).
    it('recordFailedLoginAttempt decrements even with no session key in memory', async () => {
      const { recordFailedLoginAttempt } = await import('./securityModes');
      await armDuressMode('Duress123!', 3);

      // Simulate a fresh login page: keys cleared, localStorage retained.
      keyStore.clear();

      // Attempts 1 and 2 must not trigger wipe but MUST decrement.
      expect(await recordFailedLoginAttempt()).toBe(false);
      expect(getDuressModeConfig().attemptsRemaining).toBe(2);
      expect(await recordFailedLoginAttempt()).toBe(false);
      expect(getDuressModeConfig().attemptsRemaining).toBe(1);

      // Third attempt exhausts the budget and signals wipe.
      expect(await recordFailedLoginAttempt()).toBe(true);
      expect(getDuressModeConfig().attemptsRemaining).toBe(0);
    }, 180000);
  });

  describe('Login lockout gate', () => {
    // checkIsLockedOut() reads the same LockoutConfig that
    // recordFailedLoginAttempt/resetLoginAttempts already maintained, but
    // nothing called it back — Login.tsx now gates handleLogin on it.
    it('stays unlocked below maxAttempts, locks at the threshold, clears on reset', async () => {
      const { checkIsLockedOut, recordFailedLoginAttempt, resetLoginAttempts } = await import('./securityModes');

      expect(checkIsLockedOut().locked).toBe(false);

      // Default LockoutConfig: maxAttempts = 3.
      await recordFailedLoginAttempt();
      expect(checkIsLockedOut().locked).toBe(false);
      await recordFailedLoginAttempt();
      expect(checkIsLockedOut().locked).toBe(false);
      await recordFailedLoginAttempt();
      expect(checkIsLockedOut().locked).toBe(true);

      await resetLoginAttempts();
      expect(checkIsLockedOut().locked).toBe(false);
    }, 60000);

    it('reports locked as false once lockedUntil has passed', async () => {
      const { checkIsLockedOut, saveLockoutConfig, getLockoutConfig } = await import('./securityModes');
      const cfg = getLockoutConfig();
      saveLockoutConfig({ ...cfg, attemptsMade: cfg.maxAttempts, lockedUntil: Date.now() - 1000 });

      expect(checkIsLockedOut().locked).toBe(false);
    });
  });

  describe('Duress check login-path cost', () => {
    // The duress check runs FIRST and serially in Login.tsx handleLogin, so its
    // cost is added to every login while Duress Mode is armed. The pure-JS
    // @noble Argon2id at m=256 MiB / t=3 costs ~14 s on commodity hardware
    // (the reported "20-second login"); the hash-wasm path at identical params
    // costs ~1 s. Budget is deliberately loose to stay CI-safe while still
    // failing hard if the pure-JS implementation ever creeps back in.
    it('checkIsDuressPassword stays within a WASM-scale budget at production params', async () => {
      await armDuressMode('Duress123!', 5);

      const t0 = performance.now();
      expect(await checkIsDuressPassword('Duress123!')).toBe(true);
      expect(await checkIsDuressPassword('NotTheDuressPw!')).toBe(false);
      const elapsed = performance.now() - t0;

      expect(elapsed).toBeLessThan(20000); // 2 checks; pure-JS would need ~28 s
    }, 180000);

    // Hashes armed by older builds were produced by @noble/hashes argon2idAsync.
    // Argon2id is deterministic (RFC 9106), so the WASM implementation must
    // verify them byte-for-byte. Fixture generated with @noble at
    // m=4096,t=3,p=1 — params are parsed from the PHC string, so the small
    // fixture exercises the same code path as a production 256 MiB hash.
    it('verifies a PHC hash produced by the legacy @noble implementation', async () => {
      const legacyPhc = '$argon2id$v=19$m=4096,t=3,p=1$00112233445566778899aabbccddeeff$56711f06dd322bfb122c2e4cb32dd99916748e49488f37cf80fc5c6800d214e1';
      localStorage.setItem('duress_mode_config', JSON.stringify({
        armed: true,
        passwordHash: legacyPhc,
        maxAttempts: 5,
        attemptsRemaining: 5,
        salt: '00112233445566778899aabbccddeeff',
      }));

      expect(await checkIsDuressPassword('legacy-duress-pw')).toBe(true);
      expect(await checkIsDuressPassword('wrong-password')).toBe(false);
    }, 60000);
  });
});
