import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { getEnvSmtpConfig, parseSmtpTestFilter } from '../lib/smtpConfig.js';

describe('getEnvSmtpConfig', () => {
  const saved = {};
  const KEYS = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_EMAIL', 'SMTP_PASSWORD', 'SMTP_PROTOCOL'];

  beforeEach(() => { KEYS.forEach(k => { saved[k] = process.env[k]; delete process.env[k]; }); });
  afterEach(() => { KEYS.forEach(k => { if (saved[k] !== undefined) process.env[k] = saved[k]; else delete process.env[k]; }); });

  it('returns null when SMTP_HOST is blank', () => {
    assert.equal(getEnvSmtpConfig(), null);
  });

  it('returns config object when all required vars are set', () => {
    process.env.SMTP_HOST = 'smtp.example.com';
    process.env.SMTP_PORT = '587';
    process.env.SMTP_EMAIL = 'no-reply@example.com';
    process.env.SMTP_PASSWORD = 'secret';
    process.env.SMTP_PROTOCOL = 'STARTTLS';
    const cfg = getEnvSmtpConfig();
    assert.deepEqual(cfg, {
      host: 'smtp.example.com',
      port: 587,
      protocol: 'starttls',
      username: 'no-reply@example.com',
      password: 'secret',
      fromName: 'PWDnow',
    });
  });

  it('normalises SSL/TLS to ssl_tls', () => {
    process.env.SMTP_HOST = 'smtp.example.com';
    process.env.SMTP_EMAIL = 'a@b.com';
    process.env.SMTP_PASSWORD = 'x';
    process.env.SMTP_PROTOCOL = 'SSL/TLS';
    const cfg = getEnvSmtpConfig();
    assert.equal(cfg.protocol, 'ssl_tls');
  });

  it('defaults port to 465 for ssl_tls, 587 for starttls, 25 for smtp', () => {
    process.env.SMTP_HOST = 'h'; process.env.SMTP_EMAIL = 'a@b.com'; process.env.SMTP_PASSWORD = 'x';
    process.env.SMTP_PROTOCOL = 'SSL/TLS';
    assert.equal(getEnvSmtpConfig().port, 465);
    process.env.SMTP_PROTOCOL = 'STARTTLS';
    assert.equal(getEnvSmtpConfig().port, 587);
    process.env.SMTP_PROTOCOL = 'SMTP';
    assert.equal(getEnvSmtpConfig().port, 25);
  });
});

describe('parseSmtpTestFilter', () => {
  it('returns ALL_TESTS for full', () => {
    const f = parseSmtpTestFilter('full');
    assert(f.has('spf') && f.has('dkim') && f.has('dmarc') && f.has('bimi') && f.has('vmc'));
  });

  it('returns empty set for none', () => {
    assert.equal(parseSmtpTestFilter('none').size, 0);
  });

  it('returns full set when blank (defaults to full)', () => {
    const f = parseSmtpTestFilter('');
    assert(f.has('spf') && f.has('dmarc'));
  });

  it('parses semicolon-separated values', () => {
    const f = parseSmtpTestFilter('SPF;DKIM;DMARC');
    assert(f.has('spf') && f.has('dkim') && f.has('dmarc'));
    assert(!f.has('bimi'));
  });

  it('accepts DMARK as alias for dmarc', () => {
    const f = parseSmtpTestFilter('DMARK');
    assert(f.has('dmarc'));
  });
});
