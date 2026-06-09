# SMTP Env Config + Autofill Env Var Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add env-file-based SMTP configuration as a system-level fallback for email OTP, and ensure `VITE_BROWSER_AUTOFILL=false` is present in `.env` and applied to all password inputs that are missing it.

**Architecture:** SMTP credentials from `.env` are parsed once at startup into a shared module (`lib/smtpConfig.js`) and used as a fallback when no per-user SMTP config exists in the vault. `SMTP_TEST` controls which DNS/auth checks are validated at startup. `VITE_BROWSER_AUTOFILL` is already partially wired in the frontend — this plan adds the missing `.env` entry and fills remaining input gaps.

**Tech Stack:** Node.js (ESM), nodemailer (already a dep), dotenv (already used), React 19 + TypeScript, Vite (VITE_ prefix env vars bundled at build time).

---

## Current state (read before touching anything)

| Item | Status |
|---|---|
| `VITE_BROWSER_AUTOFILL` in `.env.example` | ✅ Already present with comment |
| `VITE_BROWSER_AUTOFILL` in `.env` | ❌ Missing — must be added |
| `BROWSER_AUTOFILL` consumed in `src/utils/cardUtils.ts` | ✅ Exported correctly |
| `autoComplete` in `Login.tsx` (lines 961, 1079) | ✅ Reads `import.meta.env.VITE_BROWSER_AUTOFILL` |
| `autoComplete` in `Register.tsx` | ✅ Hardcoded `"off"` / `"new-password"` — correct, no change needed |
| `autoComplete` in `AddCredential.tsx` | ✅ Uses `BROWSER_AUTOFILL` from cardUtils |
| `autoComplete` in `SecurityModesSection.tsx` (lines 469, 569, 654) | ❌ Missing `autoComplete` attribute on 3 password inputs |
| SMTP env vars in `.env` | ❌ Missing — all empty/commented |
| SMTP env vars in `.env.example` | ❌ Missing — section needs to be added |
| `lib/smtpConfig.js` | ❌ Does not exist |
| `authRoutes.js` env SMTP fallback | ❌ Does not fall back to env; returns false if no per-user config |

---

## File map

| File | Action | Responsibility |
|---|---|---|
| `web/.env` | Modify | Add `VITE_BROWSER_AUTOFILL=false` + SMTP section (all values blank/commented) |
| `web/.env.example` | Modify | Add documented SMTP section after existing `VITE_BROWSER_AUTOFILL` entry |
| `web/lib/smtpConfig.js` | Create | Parse `SMTP_*` env vars; export `getEnvSmtpConfig()` and `parseSmtpTestFilter()` |
| `web/auth.js` | Modify | Call `validateEnvSmtp()` from smtpConfig.js after `initAuth()` |
| `web/routes/authRoutes.js` | Modify | Fall back to `getEnvSmtpConfig()` in two `sendOtpEmail` call sites; filter smtp-check tests per `SMTP_TEST` |
| `web/src/pages/Settings/SecurityModesSection.tsx` | Modify | Add `autoComplete="new-password"` to 3 bare `type="password"` inputs |
| `web/tests/smtpConfig.test.js` | Create | Unit tests for env parsing and test-filter logic |

---

## Task 1: Update `.env` and `.env.example`

**Files:**
- Modify: `web/.env`
- Modify: `web/.env.example`

- [ ] **Step 1: Add `VITE_BROWSER_AUTOFILL=false` to `.env`**

The current `.env` ends with the SSL section. Append after the last existing line:

```
# ── Browser Autofill ──────────────────────────────────────────────────────────
# Allow the browser's built-in password manager (Chrome, Firefox, etc.) to
# autofill credentials into PWDnow's own fields.
# Default: false — PWDnow is its own password manager; browser suggestions interfere.
# Set to true if you prefer the browser to offer autofill inside the app.
VITE_BROWSER_AUTOFILL=false
```

- [ ] **Step 2: Add SMTP section to `.env`** (all values blank — user fills them in)

Append after the `VITE_BROWSER_AUTOFILL` block:

```
# ── SMTP Configuration ────────────────────────────────────────────────────────
# System-level SMTP fallback used when no per-user SMTP config exists.
# Leave all blank to disable (users configure SMTP via the Settings GUI instead).
#
# SMTP_PROTOCOL: SMTP | SSL/TLS | STARTTLS
# SMTP_PORT:     25 (SMTP) | 587 (STARTTLS) | 465 (SSL/TLS)
# SMTP_HOST:     your outgoing mail server hostname
# SMTP_EMAIL:    the From address (also used as the SMTP username)
# SMTP_PASSWORD: SMTP account password or app-password
#
# SMTP_TEST: Which email-auth checks to run at startup to validate this config.
#   none               — skip all validation
#   full               — all checks: MX, SPF, DKIM, DMARC, BIMI, VMC (default)
#   Individual values  — SPF | DKIM | DMARC | BIMI | VMC
#   Combinations       — semicolon-separated, e.g. SPF;DKIM;DMARC
SMTP_PROTOCOL=
SMTP_PORT=
SMTP_HOST=
SMTP_EMAIL=
SMTP_PASSWORD=
SMTP_TEST=full
```

- [ ] **Step 3: Add the same SMTP section to `.env.example`**

`.env.example` already has `VITE_BROWSER_AUTOFILL=false` as the last entry. Append after it:

```
# ── SMTP Configuration ────────────────────────────────────────────────────────
# System-level SMTP fallback used when no per-user SMTP config exists.
# Leave all blank to disable (users configure SMTP via the Settings GUI instead).
#
# SMTP_PROTOCOL: SMTP | SSL/TLS | STARTTLS
# SMTP_PORT:     25 (SMTP) | 587 (STARTTLS) | 465 (SSL/TLS)
# SMTP_HOST:     your outgoing mail server hostname
# SMTP_EMAIL:    the From address (also used as the SMTP username)
# SMTP_PASSWORD: SMTP account password or app-password
#
# SMTP_TEST: Which email-auth checks to run at startup to validate this config.
#   none               — skip all validation
#   full               — all checks: MX, SPF, DKIM, DMARC, BIMI, VMC (default)
#   Individual values  — SPF | DKIM | DMARC | BIMI | VMC
#   Combinations       — semicolon-separated, e.g. SPF;DKIM;DMARC
SMTP_PROTOCOL=
SMTP_PORT=
SMTP_HOST=
SMTP_EMAIL=
SMTP_PASSWORD=
SMTP_TEST=full
```

- [ ] **Step 4: Commit**

```bash
git add web/.env web/.env.example
git commit -m "chore(env): add VITE_BROWSER_AUTOFILL and SMTP env config section"
```

---

## Task 2: Create `lib/smtpConfig.js`

**Files:**
- Create: `web/lib/smtpConfig.js`
- Create: `web/tests/smtpConfig.test.js`

- [ ] **Step 1: Write the failing test**

```js
// web/tests/smtpConfig.test.js
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

// We import the module after setting env vars so we can test different configs.
// Reset module cache between tests by using a helper that re-evaluates the functions.
// Since these are pure functions over process.env, we can just call them directly.
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

  it('returns empty set when blank (defaults to full)', () => {
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/smtpConfig.test.js 2>&1 | head -20
```

Expected: `ERR_MODULE_NOT_FOUND` for `lib/smtpConfig.js`

- [ ] **Step 3: Implement `lib/smtpConfig.js`**

```js
// web/lib/smtpConfig.js

const ALL_TESTS = new Set(['spf', 'dkim', 'dmarc', 'bimi', 'vmc']);

const PROTOCOL_MAP = {
  'smtp':    'smtp',
  'ssl/tls': 'ssl_tls',
  'ssl_tls': 'ssl_tls',
  'starttls':'starttls',
};

const DEFAULT_PORT = { ssl_tls: 465, starttls: 587, smtp: 25 };

/**
 * Returns the nodemailer transport options object for a given protocol string.
 * Used by sendOtpEmail and the smtp-check endpoint.
 */
export function smtpTransportOpts(protocol) {
  if (protocol === 'ssl_tls') return { secure: true };
  if (protocol === 'starttls') return { secure: false, requireTLS: true };
  return { secure: false };
}

/**
 * Parses SMTP_* env vars and returns a config blob compatible with sendOtpEmail,
 * or null when SMTP_HOST is blank.
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
 * Parses SMTP_TEST env var (or a raw string) into a Set of test names to run.
 * Returns ALL_TESTS for 'full' or blank; empty Set for 'none'.
 * Recognises: spf, dkim, dmarc (also dmark), bimi, vmc — semicolon-separated.
 */
export function parseSmtpTestFilter(raw) {
  const val = (raw ?? process.env.SMTP_TEST ?? 'full').trim().toLowerCase();
  if (!val || val === 'full') return new Set(ALL_TESTS);
  if (val === 'none') return new Set();
  const result = new Set();
  for (const token of val.split(';')) {
    const t = token.trim();
    if (t === 'dmark') { result.add('dmarc'); continue; }  // common misspelling
    if (ALL_TESTS.has(t)) result.add(t);
  }
  return result;
}

/**
 * Run at server startup when SMTP env vars are present.
 * Performs DNS checks according to SMTP_TEST and logs results.
 * Never throws — failures are logged, not fatal.
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

  const { promises: dns } = await import('dns');
  const nodemailer = (await import('nodemailer')).default;

  const parts = cfg.host.split('.');
  const domain = parts.length >= 2 ? parts.slice(-2).join('.') : cfg.host;
  const results = [];

  try {
    const checks = [];
    if (filter.has('spf') || filter.has('dkim')) checks.push(dns.resolveTxt(domain).catch(() => null));
    else checks.push(Promise.resolve(null));
    if (filter.has('dmarc')) checks.push(dns.resolveTxt(`_dmarc.${domain}`).catch(() => null));
    else checks.push(Promise.resolve(null));
    if (filter.has('bimi') || filter.has('vmc')) checks.push(dns.resolveTxt(`default._bimi.${domain}`).catch(() => null));
    else checks.push(Promise.resolve(null));

    const [txtRecs, dmarcRecs, bimiRecs] = await Promise.all(checks);

    if (filter.has('spf')) {
      const spf = txtRecs?.flat().find(r => r.startsWith('v=spf1'));
      results.push(spf ? '✓ SPF' : '✗ SPF (no record)');
    }
    if (filter.has('dkim')) {
      // Quick check: look for google/default/selector1 selectors
      const dkimSelectors = ['google', 'default', 'selector1', 'selector2', 'k1', 'dkim', 'mail'];
      const dkimFound = await Promise.any(
        dkimSelectors.map(s => dns.resolveTxt(`${s}._domainkey.${domain}`))
      ).catch(() => null);
      results.push(dkimFound ? '✓ DKIM' : '✗ DKIM (no common selector found)');
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

  // Always attempt SMTP connection verify
  try {
    const { secure, requireTLS } = smtpTransportOpts(cfg.protocol);
    const t = nodemailer.createTransport({
      host: cfg.host, port: cfg.port, secure,
      ...(requireTLS ? { requireTLS: true } : {}),
      auth: { user: cfg.username, pass: cfg.password },
      connectionTimeout: 8000, greetingTimeout: 8000, socketTimeout: 8000,
      tls: { rejectUnauthorized: false },
    });
    await t.verify();
    results.push('✓ SMTP connection');
  } catch (e) {
    results.push(`✗ SMTP connection (${e.code ?? e.message})`);
  }

  console.log(`[smtp] Results: ${results.join(' | ')}`);
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/smtpConfig.test.js 2>&1
```

Expected: all tests pass (no failures).

- [ ] **Step 5: Commit**

```bash
git add web/lib/smtpConfig.js web/tests/smtpConfig.test.js
git commit -m "feat(smtp): add lib/smtpConfig.js for env-based SMTP parsing and startup validation"
```

---

## Task 3: Wire env SMTP fallback into server and auth routes

**Files:**
- Modify: `web/auth.js` (add `validateEnvSmtp()` call in `initAuth`)
- Modify: `web/routes/authRoutes.js` (2 call sites + smtp-check test filter)

- [ ] **Step 1: Call `validateEnvSmtp()` in `auth.js` after `initAuth`**

In `auth.js`, the `initAuth` function at line 14 initialises the data dir and MASTER_KEY. After the pre-warm calls at lines 36-40, add:

```js
// In auth.js, add at top of file (with other imports):
import { validateEnvSmtp } from './lib/smtpConfig.js';
```

Then at the end of `initAuth()`, after `derivedKey('users/enc', 32);` (line 40), add:

```js
  // Validate env-based SMTP config asynchronously — never blocks startup.
  validateEnvSmtp().catch(e => console.error('[smtp] Startup validation error:', e.message));
```

- [ ] **Step 2: Add env SMTP fallback at the two `sendOtpEmail` call sites in `authRoutes.js`**

Add the import at the top of `authRoutes.js` (after the existing imports, before the `pbkdf2Async` line):

```js
import { getEnvSmtpConfig } from '../lib/smtpConfig.js';
```

**Call site 1** — login OTP (around line 904 in the current file, inside `app.post('/api/auth/login', ...)`):

Find this block:
```js
        const smtpCfg  = readUserBlob(u.id, 'smtp_config', null);
        const toEmail  = typeof profile.email === 'string' ? profile.email.trim() : '';
        if (toEmail && smtpCfg) {
```

Replace with:
```js
        const smtpCfg  = readUserBlob(u.id, 'smtp_config', null) ?? getEnvSmtpConfig();
        const toEmail  = typeof profile.email === 'string' ? profile.email.trim() : '';
        if (toEmail && smtpCfg) {
```

**Call site 2** — setup OTP (around line 1289 in the current file, inside `app.post('/api/auth/send-setup-otp', ...)`):

Find this block:
```js
    const smtpCfg = readUserBlob(req.user.id, 'smtp_config', null);
    try {
```

Replace with:
```js
    const smtpCfg = readUserBlob(req.user.id, 'smtp_config', null) ?? getEnvSmtpConfig();
    try {
```

- [ ] **Step 3: Use `parseSmtpTestFilter` in the `/api/auth/smtp-check` endpoint**

Add to the imports in `authRoutes.js` (same line as the previous import):

```js
import { getEnvSmtpConfig, parseSmtpTestFilter } from '../lib/smtpConfig.js';
```

In the `/api/auth/smtp-check` handler (around line 1156), add after the `result` object is initialised and before the `Promise.allSettled` DNS block:

```js
    // Honour SMTP_TEST env filter — skip checks not in the active filter set.
    // GUI users can always override via the `tests` body param.
    const reqTests = typeof req.body?.tests === 'string' ? req.body.tests : null;
    const testFilter = parseSmtpTestFilter(reqTests ?? process.env.SMTP_TEST ?? 'full');
    const runAll = testFilter.size === ALL_TESTS_SIZE;
```

Add constant after the imports in `authRoutes.js`:
```js
const ALL_TESTS_SIZE = 5; // spf, dkim, dmarc, bimi, vmc
```

Then wrap each DNS check branch that feeds into `result.spf`, `result.dkim`, etc., with a filter check. For example, find the section that processes `txtR` for SPF:

```js
    if (txtR.status === 'fulfilled') {
      const spf = txtR.value.flat().find(r => r.startsWith('v=spf1'));
      if (spf) { result.spf.found = true; result.spf.record = spf; }
    }
```

Replace with:
```js
    if (testFilter.has('spf') && txtR.status === 'fulfilled') {
      const spf = txtR.value.flat().find(r => r.startsWith('v=spf1'));
      if (spf) { result.spf.found = true; result.spf.record = spf; }
    }
```

Apply the same `testFilter.has(...)` guard to the dkim, dmarc, bimi, and vmc result processing blocks. The SMTP connection check at the end of the handler is always run (not gated by testFilter) when MX is found, which is correct behaviour.

- [ ] **Step 4: Run the existing tests to confirm nothing broke**

```bash
cd /home/pwd-vm/PWDnow/web && npm run test 2>&1 | tail -20
```

Expected: same pass/fail ratio as before.

- [ ] **Step 5: Commit**

```bash
git add web/auth.js web/routes/authRoutes.js
git commit -m "feat(smtp): wire env SMTP config fallback and SMTP_TEST filter into auth routes"
```

---

## Task 4: Fix missing `autoComplete` on Settings password inputs

**Files:**
- Modify: `web/src/pages/Settings/SecurityModesSection.tsx` (3 inputs at lines 469, 569, 654)

The `VITE_BROWSER_AUTOFILL` constant is exported from `src/utils/cardUtils.ts` as `BROWSER_AUTOFILL`. All three inputs in `SecurityModesSection.tsx` are security-related password fields (travel mode password, disable travel password, duress password). When autofill is disabled these should not be autocompleted.

- [ ] **Step 1: Import `BROWSER_AUTOFILL` in SecurityModesSection.tsx**

At the top of `SecurityModesSection.tsx`, find the existing imports and add:

```tsx
import { BROWSER_AUTOFILL } from '@/utils/cardUtils';
```

- [ ] **Step 2: Add `autoComplete` to the three password inputs**

**Input 1** — Travel mode confirm password (line ~469). Find:
```tsx
<input type="password" value={confirmTravelPassword}
```
Add `autoComplete` prop on the same element:
```tsx
<input type="password" autoComplete={BROWSER_AUTOFILL ? 'new-password' : 'off'} value={confirmTravelPassword}
```

**Input 2** — Disable travel password (line ~569). Find:
```tsx
<input type="password" value={disableTravelPw}
```
Add:
```tsx
<input type="password" autoComplete={BROWSER_AUTOFILL ? 'current-password' : 'off'} value={disableTravelPw}
```

**Input 3** — Duress confirm password (line ~654). Find:
```tsx
<input type="password" value={confirmDuressPassword}
```
Add:
```tsx
<input type="password" autoComplete={BROWSER_AUTOFILL ? 'new-password' : 'off'} value={confirmDuressPassword}
```

- [ ] **Step 3: Run TypeScript check**

```bash
cd /home/pwd-vm/PWDnow/web && npm run lint 2>&1 | tail -10
```

Expected: 0 errors.

- [ ] **Step 4: Commit**

```bash
git add web/src/pages/Settings/SecurityModesSection.tsx
git commit -m "fix(autofill): apply BROWSER_AUTOFILL env control to SecurityModesSection password inputs"
```

---

## Self-review checklist

| Requirement | Covered in task |
|---|---|
| `AUTO_FILL=false` / `VITE_BROWSER_AUTOFILL=false` added to `.env` | Task 1, Step 1 |
| SMTP section in `.env` (blank by default) | Task 1, Step 2 |
| SMTP section in `.env.example` (documented) | Task 1, Step 3 |
| `SMTP_PROTOCOL` choices: SMTP, SSL/TLS, STARTTLS | Task 2, `lib/smtpConfig.js` |
| `SMTP_PORT` | Task 2 |
| `SMTP_HOST` | Task 2 |
| `SMTP_EMAIL` (username / from address) | Task 2 |
| `SMTP_PASSWORD` | Task 2 |
| `SMTP_TEST`: none, full, DMARC, SPF, BIMI, DKIM, VMC, combinations | Task 2 + Task 3 |
| `DMARK` accepted as alias for `DMARC` | Task 2, `parseSmtpTestFilter` |
| Startup validation of env SMTP config | Task 2 `validateEnvSmtp` + Task 3 `auth.js` |
| Env SMTP used as fallback for login OTP | Task 3, call site 1 |
| Env SMTP used as fallback for setup OTP | Task 3, call site 2 |
| `SMTP_TEST` filter respected in smtp-check API | Task 3, Step 3 |
| Autofill env var wired to all password inputs | Task 4 (SecurityModesSection) |
| Unit tests for smtpConfig parsing | Task 2, Step 1 |
