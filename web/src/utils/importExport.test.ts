import { describe, it, expect } from 'vitest';
import {
  // Importers
  importChrome, importFirefox, importLastPass,
  import1PasswordCSV, import1PUX,
  importBitwardenJSON, importBitwardenCSV,
  importNordPass, importKeePassXML, importKeePassCSV,
  importKeeperJSON, importKeeperCSV,
  importDashlaneJSON, importRoboForm,
  importProtonPass, importZoho, importPassky,
  importPWDnow, importPWDnowCSV, importPWDnowXML,
  importPadloc, importEnpassJSON, importButtercup,
  // Exporters
  exportToPWDnow, exportToPWDnowCSV, exportToPWDnowXML, exportToPWDnow1PUX,
  exportToBitwardenJSON, exportToBitwardenCSV,
  exportTo1PasswordCSV, exportToNordPass, exportToLastPass,
  exportToChrome, exportToFirefox,
  exportToKeePassXML, exportToKeePassCSV,
  exportToKeeperJSON, exportToKeeperCSV,
  exportToDashlaneJSON, exportToRoboForm,
  exportToProtonPass, exportToZohoCSV, exportToPassboltCSV,
  exportToPadlocJSON, exportToPasskyJSON, exportToEnpassCSV,
  exportToButtercupJSON,
  // Registry
  FORMATS, getFormat,
  // Encrypt/decrypt
  exportToPWDnowEncrypted, decryptPWDnowExport, isEncryptedPWDnow,
} from './importExport';
import type { Credential, Folder } from '../types';

// ── Fixtures ──────────────────────────────────────────────────────────────────

const CRED: Credential = {
  id: 'test-1', service: 'GitHub', url: 'https://github.com',
  username: 'user@example.com', password: 'S3cr3t!Pass',
  status: 'active', statusColor: '#22c55e', logo: '', folderId: 'f1',
  description: 'my note', otpSecret: 'JBSWY3DPEHPK3PXP', tags: [],
};
const CRED2: Credential = {
  id: 'test-2', service: 'Google', url: 'https://google.com',
  username: 'user2@example.com', password: 'G00gle!',
  status: 'active', statusColor: '#22c55e', logo: '', folderId: '',
  tags: [],
};
const FOLDER: Folder = { id: 'f1', label: 'Work' };
const CREDS = [CRED, CRED2];
const FOLDERS = [FOLDER];

// ── Format registry ───────────────────────────────────────────────────────────

describe('Format registry', () => {
  it('has at least 20 formats', () => {
    expect(FORMATS.length).toBeGreaterThanOrEqual(20);
  });
  it('getFormat returns correct entry', () => {
    const f = getFormat('bitwarden-json');
    expect(f?.label).toBe('Bitwarden JSON');
    expect(f?.canImport).toBe(true);
    expect(f?.canExport).toBe(true);
  });
  it('getFormat returns undefined for unknown id', () => {
    expect(getFormat('nonexistent')).toBeUndefined();
  });
  it('pwdnow-1pux is export-only', () => {
    const f = getFormat('pwdnow-1pux');
    expect(f?.canExport).toBe(true);
    expect(f?.canImport).toBe(false);
  });
  it('1password-1pux is import-only', () => {
    const f = getFormat('1password-1pux');
    expect(f?.canImport).toBe(true);
    expect(f?.canExport).toBe(false);
  });
});

// ── PWDnow JSON ───────────────────────────────────────────────────────────────

describe('PWDnow JSON', () => {
  it('round-trips credentials', () => {
    const json = exportToPWDnow(CREDS, FOLDERS);
    const result = importPWDnow(json);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].service).toBe('GitHub');
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
    expect(result.credentials[0].username).toBe('user@example.com');
    expect(result.detectedFormat).toBe('pwdnow-json');
  });
  it('includes folders in export', () => {
    const parsed = JSON.parse(exportToPWDnow(CREDS, FOLDERS));
    expect(parsed.folders).toHaveLength(1);
    expect(parsed.folders[0].label).toBe('Work');
  });
  it('detects not-encrypted', () => {
    expect(isEncryptedPWDnow(exportToPWDnow(CREDS, FOLDERS))).toBe(false);
  });
});

// ── PWDnow Encrypted ──────────────────────────────────────────────────────────

describe('PWDnow Encrypted', () => {
  it('encrypts and decrypts correctly', async () => {
    const enc = await exportToPWDnowEncrypted(CREDS, FOLDERS, 'myPassphrase123');
    expect(isEncryptedPWDnow(enc)).toBe(true);
    const plain = await decryptPWDnowExport(enc, 'myPassphrase123');
    const parsed = JSON.parse(plain);
    expect(parsed.credentials).toHaveLength(2);
    expect(parsed.credentials[0].password).toBe('S3cr3t!Pass');
  });
  it('throws on wrong passphrase', async () => {
    const enc = await exportToPWDnowEncrypted(CREDS, FOLDERS, 'correct');
    await expect(decryptPWDnowExport(enc, 'wrong')).rejects.toThrow();
  });
  it('encrypted JSON has required fields', async () => {
    const enc = JSON.parse(await exportToPWDnowEncrypted(CREDS, FOLDERS, 'pw'));
    expect(enc.encrypted).toBe(true);
    expect(enc.kdf).toBe('pbkdf2-sha256');
    expect(enc.salt).toMatch(/^[0-9a-f]{32}$/);
    expect(enc.iv).toMatch(/^[0-9a-f]{24}$/);
    expect(enc.ciphertext).toBeTruthy();
  });
});

// ── PWDnow CSV ────────────────────────────────────────────────────────────────

describe('PWDnow CSV', () => {
  it('round-trips credentials', () => {
    const csv = exportToPWDnowCSV(CREDS);
    const result = importPWDnowCSV(csv);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].service).toBe('GitHub');
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
  it('has correct header', () => {
    expect(exportToPWDnowCSV(CREDS).split('\n')[0]).toBe('name,url,username,password,notes,otp_secret,folder');
  });
});

// ── PWDnow XML ────────────────────────────────────────────────────────────────

describe('PWDnow XML', () => {
  it('produces valid XML with credentials', () => {
    const xml = exportToPWDnowXML(CREDS, FOLDERS);
    expect(xml).toContain('<?xml version="1.0"');
    expect(xml).toContain('<KeePassFile>');
    expect(xml).toContain('GitHub');
    expect(xml).toContain('S3cr3t!Pass');
  });
  it('round-trips via KeePass XML import', () => {
    const xml = exportToPWDnowXML(CREDS, FOLDERS);
    const result = importPWDnowXML(xml);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].service).toBe('GitHub');
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
  it('escapes XML special chars', () => {
    const cred = { ...CRED, service: 'A & B <test>', password: '"quo"' } as Credential;
    const xml = exportToPWDnowXML([cred], []);
    expect(xml).toContain('A &amp; B &lt;test&gt;');
    expect(xml).toContain('&quot;quo&quot;');
  });
});

// ── PWDnow 1PUX ───────────────────────────────────────────────────────────────

describe('PWDnow 1PUX', () => {
  it('returns a Uint8Array (ZIP bytes)', () => {
    const bytes = exportToPWDnow1PUX(CREDS, FOLDERS);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBeGreaterThan(100);
  });
  it('starts with PK ZIP signature', () => {
    const bytes = exportToPWDnow1PUX(CREDS, FOLDERS);
    // Local file header signature: PK\x03\x04
    expect(bytes[0]).toBe(0x50); // P
    expect(bytes[1]).toBe(0x4B); // K
    expect(bytes[2]).toBe(0x03);
    expect(bytes[3]).toBe(0x04);
  });
  it('contains export.data filename in ZIP', () => {
    const bytes = exportToPWDnow1PUX(CREDS, FOLDERS);
    const text = new TextDecoder('latin1').decode(bytes);
    expect(text).toContain('export.data');
  });
});

// ── 1PUX import ───────────────────────────────────────────────────────────────

describe('1PUX import', () => {
  const onepux = JSON.stringify({
    accounts: [{
      attrs: { accountName: 'Test', name: 'Test' },
      vaults: [{
        attrs: { name: 'Personal' },
        items: [{
          state: 'active', categoryUuid: '001',
          details: {
            loginFields: [
              { designation: 'username', name: 'username', type: 'T', value: 'alice@example.com' },
              { designation: 'password', name: 'password', type: 'P', value: 'hunter2' },
            ],
            notes: 'some note', sections: [],
          },
          overview: { title: 'Example', url: 'https://example.com', urls: [{ l: 'website', u: 'https://example.com' }] },
        }],
      }],
    }],
  });

  it('imports username and password', () => {
    const result = import1PUX(onepux);
    expect(result.credentials).toHaveLength(1);
    expect(result.credentials[0].username).toBe('alice@example.com');
    expect(result.credentials[0].password).toBe('hunter2');
    expect(result.credentials[0].service).toBe('Example');
  });
  it('skips archived items', () => {
    const withArchived = JSON.parse(onepux);
    withArchived.accounts[0].vaults[0].items[0].state = 'archived';
    expect(import1PUX(JSON.stringify(withArchived)).credentials).toHaveLength(0);
  });
});

// ── Chrome / Firefox ──────────────────────────────────────────────────────────

describe('Chrome CSV', () => {
  const csv = 'name,url,username,password,note\nGitHub,https://github.com,alice,secret,my note';
  it('imports all fields', () => {
    const result = importChrome(csv);
    expect(result.credentials).toHaveLength(1);
    expect(result.credentials[0].service).toBe('GitHub');
    expect(result.credentials[0].username).toBe('alice');
    expect(result.credentials[0].password).toBe('secret');
  });
  it('round-trips', () => {
    const csv2 = exportToChrome(CREDS);
    const result = importChrome(csv2);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
});

describe('Firefox CSV', () => {
  it('round-trips', () => {
    const csv = exportToFirefox(CREDS);
    const result = importFirefox(csv);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
});

// ── LastPass ──────────────────────────────────────────────────────────────────

describe('LastPass CSV', () => {
  const csv = 'url,username,password,totp,extra,name,grouping,fav\nhttps://github.com,alice,secret,,my note,GitHub,work,0';
  it('imports all fields', () => {
    const result = importLastPass(csv);
    expect(result.credentials).toHaveLength(1);
    expect(result.credentials[0].service).toBe('GitHub');
    expect(result.credentials[0].password).toBe('secret');
  });
  it('round-trips', () => {
    const exported = exportToLastPass(CREDS);
    expect(exported.split('\n')[0]).toContain('url,username,password');
    const result = importLastPass(exported);
    expect(result.credentials).toHaveLength(2);
  });
});

// ── 1Password CSV ─────────────────────────────────────────────────────────────

describe('1Password CSV', () => {
  it('round-trips', () => {
    const csv = exportTo1PasswordCSV(CREDS);
    expect(csv.split('\n')[0]).toBe('Title,Username,Password,URL,Notes,OTPAuth');
    const result = import1PasswordCSV(csv);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].service).toBe('GitHub');
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
  it('includes OTP URI', () => {
    const csv = exportTo1PasswordCSV([CRED]);
    expect(csv).toContain('otpauth://totp/');
    expect(csv).toContain('JBSWY3DPEHPK3PXP');
  });
});

// ── Bitwarden ─────────────────────────────────────────────────────────────────

describe('Bitwarden JSON', () => {
  it('round-trips', () => {
    const json = exportToBitwardenJSON(CREDS, FOLDERS);
    const result = importBitwardenJSON(json);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
  it('throws on encrypted export', () => {
    expect(() => importBitwardenJSON(JSON.stringify({ encrypted: true }))).toThrow();
  });
  it('exports encrypted:false flag', () => {
    const parsed = JSON.parse(exportToBitwardenJSON(CREDS, FOLDERS));
    expect(parsed.encrypted).toBe(false);
    expect(parsed.items).toHaveLength(2);
  });
});

describe('Bitwarden CSV', () => {
  it('round-trips', () => {
    const csv = exportToBitwardenCSV(CREDS, FOLDERS);
    const result = importBitwardenCSV(csv);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
});

// ── NordPass ──────────────────────────────────────────────────────────────────

describe('NordPass CSV', () => {
  it('round-trips', () => {
    const csv = exportToNordPass(CREDS);
    const result = importNordPass(csv);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].service).toBe('GitHub');
  });
});

// ── KeePass XML ───────────────────────────────────────────────────────────────

describe('KeePass XML', () => {
  it('round-trips', () => {
    const xml = exportToKeePassXML(CREDS, FOLDERS);
    const result = importKeePassXML(xml);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
    expect(result.credentials[0].service).toBe('GitHub');
  });
  it('preserves OTP', () => {
    const xml = exportToKeePassXML([CRED], []);
    const result = importKeePassXML(xml);
    expect(result.credentials[0].otpSecret).toBe('JBSWY3DPEHPK3PXP');
  });
});

describe('KeePass CSV', () => {
  it('round-trips', () => {
    const csv = exportToKeePassCSV(CREDS);
    const result = importKeePassCSV(csv);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
});

// ── Keeper ────────────────────────────────────────────────────────────────────

describe('Keeper JSON', () => {
  it('round-trips', () => {
    const json = exportToKeeperJSON(CREDS, FOLDERS);
    const result = importKeeperJSON(json);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
});

describe('Keeper CSV', () => {
  it('round-trips', () => {
    const csv = exportToKeeperCSV(CREDS, FOLDERS);
    const result = importKeeperCSV(csv);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].username).toBe('user@example.com');
  });
});

// ── Dashlane ──────────────────────────────────────────────────────────────────

describe('Dashlane JSON', () => {
  it('round-trips', () => {
    const json = exportToDashlaneJSON(CREDS);
    const result = importDashlaneJSON(json);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
  it('imports Dashlane-native format', () => {
    const data = JSON.stringify({ credentials: [{ title: 'Test', url: 'https://test.com', login: 'alice', password: 'pw123', note: '' }] });
    const result = importDashlaneJSON(data);
    expect(result.credentials[0].username).toBe('alice');
    expect(result.credentials[0].password).toBe('pw123');
  });
});

// ── RoboForm ──────────────────────────────────────────────────────────────────

describe('RoboForm CSV', () => {
  it('round-trips', () => {
    const csv = exportToRoboForm(CREDS, FOLDERS);
    const result = importRoboForm(csv);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
});

// ── Proton Pass ───────────────────────────────────────────────────────────────

describe('Proton Pass JSON', () => {
  it('round-trips', () => {
    const json = exportToProtonPass(CREDS, FOLDERS);
    const result = importProtonPass(json);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].service).toBe('GitHub');
  });
});

// ── Zoho Vault ────────────────────────────────────────────────────────────────

describe('Zoho CSV', () => {
  it('round-trips', () => {
    const csv = exportToZohoCSV(CREDS);
    const result = importZoho(csv);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
});

// ── Padloc ────────────────────────────────────────────────────────────────────

describe('Padloc JSON', () => {
  it('round-trips', () => {
    const json = exportToPadlocJSON(CREDS, FOLDERS);
    const result = importPadloc(json);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
});

// ── Passky ────────────────────────────────────────────────────────────────────

describe('Passky JSON', () => {
  it('round-trips', () => {
    const json = exportToPasskyJSON(CREDS);
    const result = importPassky(json);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
});

// ── Enpass CSV ────────────────────────────────────────────────────────────────

describe('Enpass CSV', () => {
  it('contains passwords in cleartext', () => {
    const csv = exportToEnpassCSV(CREDS);
    expect(csv).toContain('S3cr3t!Pass');
    expect(csv).toContain('G00gle!');
  });
  it('exports correct header', () => {
    expect(exportToEnpassCSV(CREDS).split('\n')[0]).toBe('Title,URL,Username,Password,Notes,One-Time Password');
  });
});

// ── Buttercup JSON ────────────────────────────────────────────────────────────

describe('Buttercup JSON', () => {
  it('round-trips', () => {
    const json = exportToButtercupJSON(CREDS, FOLDERS);
    const result = importButtercup(json);
    expect(result.credentials).toHaveLength(2);
    expect(result.credentials[0].service).toBe('GitHub');
    expect(result.credentials[0].password).toBe('S3cr3t!Pass');
  });
});

// ── CSV with special chars ────────────────────────────────────────────────────

describe('CSV escaping', () => {
  it('handles commas in service names', () => {
    const cred = { ...CRED, service: 'Acme, Inc.', password: 'p@ss,word' } as Credential;
    const csv = exportToChrome([cred]);
    const result = importChrome(csv);
    expect(result.credentials[0].service).toBe('Acme, Inc.');
    expect(result.credentials[0].password).toBe('p@ss,word');
  });
  it('handles quotes in values', () => {
    const cred = { ...CRED, service: 'Say "hello"', password: '"quoted"' } as Credential;
    const csv = exportToChrome([cred]);
    const result = importChrome(csv);
    expect(result.credentials[0].service).toBe('Say "hello"');
    expect(result.credentials[0].password).toBe('"quoted"');
  });
});
