// web/lib/smtpConfig.js
import { promises as dns } from 'dns';
import nodemailer from 'nodemailer';

const ALL_TESTS = new Set(['spf', 'dkim', 'dmarc', 'bimi', 'vmc']);

const PROTOCOL_MAP = {
  'smtp':    'smtp',
  'ssl/tls': 'ssl_tls',
  'ssl_tls': 'ssl_tls',
  'starttls':'starttls',
};

const DEFAULT_PORT = { ssl_tls: 465, starttls: 587, smtp: 25 };

/**
 * Returns nodemailer transport option fields for a given internal protocol string.
 */
export function smtpTransportOpts(protocol) {
  if (protocol === 'ssl_tls')  return { secure: true };
  if (protocol === 'starttls') return { secure: false, requireTLS: true };
  return { secure: false };
}

/**
 * Parses SMTP_* env vars. Returns a config object compatible with sendOtpEmail,
 * or null when SMTP_HOST is not set.
 */
export function getEnvSmtpConfig() {
  const host = (process.env.SMTP_HOST || '').trim();
  if (!host) return null;

  const rawProtocol = (process.env.SMTP_PROTOCOL || 'STARTTLS').trim().toLowerCase();
  const protocol = PROTOCOL_MAP[rawProtocol] ?? 'starttls';
  const defaultPort = DEFAULT_PORT[protocol] ?? 587;
  const port = parseInt(process.env.SMTP_PORT || '', 10) || defaultPort;
  const username = (process.env.SMTP_EMAIL || '').trim();
  const password = (process.env.SMTP_PASSWORD || '').trim();

  return { host, port, protocol, username, password, fromName: 'PWDnow' };
}

/**
 * Parses SMTP_TEST env var (or a provided raw string) into a Set of test names.
 * Returns ALL_TESTS for 'full' or blank; empty Set for 'none'.
 * Accepts: spf, dkim, dmarc (+ dmark alias), bimi, vmc — semicolon-separated.
 */
export function parseSmtpTestFilter(raw) {
  const val = (raw ?? process.env.SMTP_TEST ?? 'full').trim().toLowerCase();
  if (!val || val === 'full') return new Set(ALL_TESTS);
  if (val === 'none') return new Set();
  const result = new Set();
  for (const token of val.split(';')) {
    const t = token.trim();
    if (t === 'dmark') { result.add('dmarc'); continue; }
    if (ALL_TESTS.has(t)) result.add(t);
  }
  return result;
}

/**
 * Called at server startup when SMTP env vars are present.
 * Runs DNS/connection checks according to SMTP_TEST and logs results.
 * Never throws — validation failures are non-fatal.
 */
export async function validateEnvSmtp() {
  const cfg = getEnvSmtpConfig();
  if (!cfg) return;

  const filter = parseSmtpTestFilter();
  if (filter.size === 0) {
    console.log('[smtp] Env SMTP configured. Validation disabled (SMTP_TEST=none).');
    return;
  }

  console.log(`[smtp] Env SMTP configured (${cfg.host}:${cfg.port} / ${cfg.protocol}). Running checks: ${[...filter].join(', ')}…`);

  const parts = cfg.host.split('.');
  const domain = parts.length >= 2 ? parts.slice(-2).join('.') : cfg.host;
  const results = [];

  try {
    const [txtRecs, dmarcRecs, bimiRecs] = await Promise.all([
      (filter.has('spf') || filter.has('dkim')) ? dns.resolveTxt(domain).catch(() => null) : Promise.resolve(null),
      filter.has('dmarc') ? dns.resolveTxt(`_dmarc.${domain}`).catch(() => null) : Promise.resolve(null),
      (filter.has('bimi') || filter.has('vmc')) ? dns.resolveTxt(`default._bimi.${domain}`).catch(() => null) : Promise.resolve(null),
    ]);

    if (filter.has('spf')) {
      const spf = txtRecs?.flat().find(r => r.startsWith('v=spf1'));
      results.push(spf ? '✓ SPF' : '✗ SPF (no record)');
    }
    if (filter.has('dkim')) {
      const selectors = ['google', 'default', 'selector1', 'selector2', 'k1', 'dkim', 'mail'];
      const found = await Promise.any(
        selectors.map(s => dns.resolveTxt(`${s}._domainkey.${domain}`))
      ).catch(() => null);
      results.push(found ? '✓ DKIM' : '✗ DKIM (no common selector found)');
    }
    if (filter.has('dmarc')) {
      const dmarc = dmarcRecs?.flat().find(r => r.startsWith('v=DMARC1'));
      results.push(dmarc ? `✓ DMARC (p=${dmarc.match(/\bp=([a-z]+)/i)?.[1] ?? '?'})` : '✗ DMARC (no record)');
    }
    if (filter.has('bimi')) {
      const bimi = bimiRecs?.flat().find(r => r.startsWith('v=BIMI1'));
      results.push(bimi ? '✓ BIMI' : '✗ BIMI (no record)');
    }
    if (filter.has('vmc')) {
      const bimi = bimiRecs?.flat().find(r => r.startsWith('v=BIMI1'));
      const hasVmc = bimi && /\ba=https/i.test(bimi);
      results.push(hasVmc ? '✓ VMC' : '✗ VMC (no a= field in BIMI record)');
    }
  } catch (e) {
    results.push(`✗ DNS error: ${e.message}`);
  }

  try {
    const { secure, requireTLS } = smtpTransportOpts(cfg.protocol);
    // SMTP_TLS_REJECT_UNAUTHORIZED defaults to true (secure).
    // Set to '0' only in dev environments with self-signed certs; never in production.
    const rejectUnauthorized = process.env.SMTP_TLS_REJECT_UNAUTHORIZED !== '0';
    const t = nodemailer.createTransport({
      host: cfg.host, port: cfg.port, secure,
      ...(requireTLS ? { requireTLS: true } : {}),
      auth: { user: cfg.username, pass: cfg.password },
      connectionTimeout: 8000, greetingTimeout: 8000, socketTimeout: 8000,
      tls: { rejectUnauthorized },
    });
    await t.verify();
    results.push('✓ SMTP connection');
  } catch (e) {
    results.push(`✗ SMTP connection (${e.code ?? e.message})`);
  }

  console.log(`[smtp] Results: ${results.join(' | ')}`);
}
