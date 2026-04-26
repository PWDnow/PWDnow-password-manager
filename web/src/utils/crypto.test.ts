import { describe, it, expect } from 'vitest';
import { hashPassword } from './crypto';

describe('Crypto Utilities', () => {
  it('should hash a password consistently', async () => {
    const password = 'mySuperSecretPassword123!';
    const hash1 = await hashPassword(password);
    const hash2 = await hashPassword(password);

    expect(hash1).toBeDefined();
    expect(hash1.length).toBeGreaterThan(0);
    expect(hash1).toBe(hash2); // Same input should produce same hash
  });

  it('should produce different hashes for different passwords', async () => {
    const hash1 = await hashPassword('password123');
    const hash2 = await hashPassword('password124');

    expect(hash1).not.toBe(hash2);
  });
});
