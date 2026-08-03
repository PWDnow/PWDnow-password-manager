import { promises as dnsPromises } from 'dns';
import nodemailer from 'nodemailer';
import { authMiddleware, requireAuth } from '../../lib/session.js';
import { requireCsrf } from '../../lib/csrf.js';
import { parseSmtpTestFilter } from '../../lib/smtpConfig.js';

export function mountSmtpRoutes(app) {
  app.post('/api/auth/smtp-check', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { host, port, protocol, username, password } = req.body ?? {};
    if (!host || typeof host !== 'string' || !port || !username) {
      return res.status(400).json({ error: 'invalid_input' });
    }

    const smtpHost = host.trim().toLowerCase();
    const BLOCKED_HOST_RE = /^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1|169\.254\.|fd[0-9a-f]{2}:|fc00:)/i;
    if (BLOCKED_HOST_RE.test(smtpHost)) {
      return res.status(400).json({ error: 'invalid_smtp_host' });
    }

    const parts = smtpHost.split('.');
    const domain = parts.length >= 2 ? parts.slice(-2).join('.') : smtpHost;

    const result = {
      domain,
      mx:    { found: false, records: [] },
      spf:   { found: false, record: null },
      dkim:  { found: false, selector: null, record: null },
      dmarc: { found: false, record: null, policy: null, pct: null },
      bimi:  { found: false, record: null, hasVmc: false, vmcUrl: null },
      smtp:  { ok: false, error: null },
    };

    // Honour SMTP_TEST env var — can be overridden per-request via body.tests.
    const rawTests = typeof req.body?.tests === 'string' ? req.body.tests : null;
    const testFilter = parseSmtpTestFilter(rawTests ?? process.env.SMTP_TEST ?? 'full');

    const [mxR, txtR, dmarcR, bimiR] = await Promise.allSettled([
      dnsPromises.resolveMx(domain),
      dnsPromises.resolveTxt(domain),
      dnsPromises.resolveTxt(`_dmarc.${domain}`),
      dnsPromises.resolveTxt(`default._bimi.${domain}`),
    ]);

    if (mxR.status === 'fulfilled' && mxR.value.length > 0) {
      result.mx.found = true;
      result.mx.records = mxR.value.sort((a, b) => a.priority - b.priority).slice(0, 5);
    }
    if (testFilter.has('spf') && txtR.status === 'fulfilled') {
      const spf = txtR.value.flat().find(r => r.startsWith('v=spf1'));
      if (spf) { result.spf.found = true; result.spf.record = spf; }
    }
    if (testFilter.has('dmarc') && dmarcR.status === 'fulfilled') {
      const dmarc = dmarcR.value.flat().find(r => r.startsWith('v=DMARC1'));
      if (dmarc) {
        result.dmarc.found = true; result.dmarc.record = dmarc;
        result.dmarc.policy = dmarc.match(/\bp=([a-z]+)/i)?.[1] ?? null;
        const pct = dmarc.match(/\bpct=(\d+)/i);
        result.dmarc.pct = pct ? parseInt(pct[1], 10) : null;
      }
    }
    if (testFilter.has('bimi') && bimiR.status === 'fulfilled') {
      const bimi = bimiR.value.flat().find(r => r.startsWith('v=BIMI1'));
      if (bimi) {
        result.bimi.found = true; result.bimi.record = bimi;
        const aField = bimi.match(/\ba=([^;]+)/i);
        if (aField && aField[1].trim()) {
          result.bimi.hasVmc = true; result.bimi.vmcUrl = aField[1].trim();
        }
      }
    }

    const DKIM_SELECTORS = [
      'google', 'default', 'selector1', 'selector2', 'k1', 'k2', 'k3',
      'mail', 'dkim', 'smtp', 'email', 's1', 's2',
      // Zoho
      'zoho', 'zmail', 'zm1', 'zm2', '1024', '2048',
      // Other providers
      'protonmail', 'protonmail2', 'protonmail3',
      'amazonses', 'postmark', 'mandrill', 'cm', 'mimecast',
      'dkim2', 'sig1', 'everlytickey1', 'everlytickey2',
    ];
    const dkimResults = await Promise.allSettled(
      DKIM_SELECTORS.map(async selector => {
        const txt = await dnsPromises.resolveTxt(`${selector}._domainkey.${domain}`);
        const record = txt.flat().join('');
        if (record.includes('v=DKIM1') || (record.includes('p=') && record.includes('k='))) return { selector, record };
        throw new Error('no_match');
      })
    );
    const firstDkim = dkimResults.find(r => r.status === 'fulfilled');
    if (testFilter.has('dkim') && firstDkim?.status === 'fulfilled') {
      const { selector, record } = firstDkim.value;
      result.dkim.found = true; result.dkim.selector = selector;
      result.dkim.record = record.length > 120 ? record.slice(0, 120) + '…' : record;
    }

    if (result.mx.found && password) {
      try {
        const secure = protocol === 'ssl_tls';
        const transport = nodemailer.createTransport({
          host: smtpHost, port: Number(port) || 465, secure,
          auth: { user: String(username), pass: String(password) },
          connectionTimeout: 8000, greetingTimeout: 8000, socketTimeout: 8000,
          tls: { rejectUnauthorized: false },
        });
        await transport.verify();
        result.smtp.ok = true;
      } catch (e) {
        result.smtp.error = e.code ?? e.responseCode?.toString() ?? 'connection_failed';
      }
    } else if (!result.mx.found) {
      result.smtp.error = 'no_mx_records';
    }

    res.json(result);
  });

  
}
