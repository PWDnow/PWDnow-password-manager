import { describe, it, expect } from 'vitest';
import { importFromFile } from './importExport';

describe('KDBX import support', () => {
  it('should throw ENCRYPTED_PWDNOW for .kdbx files to trigger the passphrase prompt', async () => {
    const file = new File(['fake binary data'], 'test.kdbx', { type: 'application/octet-stream' });
    await expect(importFromFile(file)).rejects.toThrow('ENCRYPTED_PWDNOW');
  });

  it('should attempt native import when passphrase is provided', async () => {
    // This will fail with 'BadSignature' because our data isn't a real KDBX, 
    // but it proves the code reached the kdbxweb parser path.
    const file = new File(['fake binary data'], 'test.kdbx', { type: 'application/octet-stream' });
    await expect(importFromFile(file, 'any-password')).rejects.toThrow(/BadSignature/i);
  });
});
