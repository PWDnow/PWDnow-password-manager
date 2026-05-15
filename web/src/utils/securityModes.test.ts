/** @vitest-environment jsdom */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { 
  enableTravelMode, disableTravelMode, 
  armDuressMode, checkIsDuressPassword,
  getTravelModeConfig, getDuressModeConfig
} from './securityModes';
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
      
      const cfg = getTravelModeConfig();
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
      
      const cfg = getTravelModeConfig();
      expect(cfg.active).toBe(false);
    }, 60000);
  });

  describe('Duress Mode', () => {
    it('should arm duress mode with Argon2id PHC hash', async () => {
      const duressPass = 'Duress123!';
      await armDuressMode(duressPass, 5);
      
      const cfg = getDuressModeConfig();
      expect(cfg.armed).toBe(true);
      expect(cfg.passwordHash).toContain('$argon2id$');
    }, 60000);

    it('should verify duress password correctly', async () => {
      const duressPass = 'Duress123!';
      await armDuressMode(duressPass, 5);
      
      const isDuress = await checkIsDuressPassword(duressPass);
      expect(isDuress).toBe(true);
      
      const isNotDuress = await checkIsDuressPassword('WrongPass');
      expect(isNotDuress).toBe(false);
    }, 60000);
  });
});
