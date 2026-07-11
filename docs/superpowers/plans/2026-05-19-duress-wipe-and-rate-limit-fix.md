# Duress Wipe Trigger & Login Rate-Limit Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three coupled bugs on the login screen — (1) duress wipe firing on every wrong password instead of after N attempts, (2) the wrong-password error message no longer displaying, and (3) `/api/auth/login-hints` 429 errors after a handful of email re-entries.

**Architecture:** All three bugs share a root cause that surfaces on the *failed login* code path in `web/src/pages/Login.tsx`. `recordFailedLoginAttempt()` was migrated to `async` (to support the new server-side duress mirror) but its sole caller still uses `const shouldWipe = recordFailedLoginAttempt();` without `await`. The returned `Promise<boolean>` is always truthy, so the wipe branch is taken on every wrong password — destroying localStorage and redirecting before the `setError(...)` call can run. The 429 problem is independent: `login-hints` shares the same 10-req/5min IP limiter as the destructive `/api/auth/login` endpoint, so the cheap email-step lookup gets blocked after very few attempts.

**Tech Stack:** TypeScript + React 19 (frontend), Express (server), Vitest (unit), Playwright (E2E).

---

## File Structure

- **Modify** `web/src/pages/Login.tsx` — fix the missing `await` at the wipe-decision call site; tighten the failed-login flow so the error renders.
- **Modify** `web/auth.js` — split the login rate-limit budget so `login-hints` has its own (more generous) counter, leaving the destructive `/api/auth/login` budget unchanged.
- **Modify** `web/src/utils/securityModes.test.ts` — add regression tests covering `recordFailedLoginAttempt` returning `false` until `attemptsRemaining === 0`, and `true` only on the exhausting attempt.
- **Create** `web/e2e/duress-wipe-trigger.spec.ts` — Playwright E2E proving the wipe only triggers after N consecutive wrong passwords and that the error renders on each non-terminal attempt.

---

## Task 1: Regression test for `recordFailedLoginAttempt` exhaustion threshold

**Files:**
- Modify: `web/src/utils/securityModes.test.ts` (append inside the existing `describe('Duress Mode', () => { ... })`)

- [ ] **Step 1: Write the failing test**

Append this block inside the existing `describe('Duress Mode', ...)` in `securityModes.test.ts`, alongside the other duress regression tests:

```ts
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
```

- [ ] **Step 2: Run test to verify it passes (already correct behavior server-side)**

Run: `npx vitest run src/utils/securityModes.test.ts -t "attemptsRemaining hits 0" --no-coverage`
Expected: PASS — this test characterises the *correct* contract; the bug is in the *caller*, not in `recordFailedLoginAttempt` itself.

- [ ] **Step 3: Commit**

```bash
cd /home/pwd-vm/PWDnow/web
git add src/utils/securityModes.test.ts
git commit -m "test(duress): pin recordFailedLoginAttempt exhaustion contract"
```

---

## Task 2: Fix the missing `await` on the wipe-decision call

**Files:**
- Modify: `web/src/pages/Login.tsx:708-720`

- [ ] **Step 1: Inspect current code**

Read `web/src/pages/Login.tsx` around line 708 to confirm the current state:

```bash
sed -n '707,720p' web/src/pages/Login.tsx
```

Expected output (the bug):

```
    // Both daemon and offline auth failed
    const shouldWipe = recordFailedLoginAttempt();
    if (shouldWipe) {
      await wipeVaultData(daemon.isConnected ? daemon : undefined);
      window.location.replace('/login');
      return;
    }
    const cfg = getDuressModeConfig();
    const remaining = cfg.armed ? ` (${cfg.attemptsRemaining} attempt${cfg.attemptsRemaining !== 1 ? 's' : ''} remaining)` : '';
    setError(t('login.invalidCredentials', 'Invalid master password.') + remaining);
    setLoading(false);
```

- [ ] **Step 2: Apply the fix**

Replace the block above with:

```ts
    // Both daemon and offline auth failed.
    // IMPORTANT: `recordFailedLoginAttempt` is async (touches encrypted
    // localStorage + server mirror). Without `await`, `shouldWipe` is a
    // Promise — always truthy — so the wipe branch would fire on every wrong
    // password, destroying localStorage and pre-empting `setError()`.
    const shouldWipe = await recordFailedLoginAttempt();
    if (shouldWipe) {
      await wipeVaultData(daemon.isConnected ? daemon : undefined);
      window.location.replace('/login');
      return;
    }
    const cfg = getDuressModeConfig();
    const remaining = cfg.armed
      ? ` (${cfg.attemptsRemaining} attempt${cfg.attemptsRemaining !== 1 ? 's' : ''} remaining)`
      : '';
    setError(t('login.invalidCredentials', 'Invalid master password.') + remaining);
    setLoading(false);
```

Use the Edit tool with `old_string` exactly matching the existing block (including indentation) and `new_string` set to the corrected block.

- [ ] **Step 3: Type-check**

Run: `cd web && npx tsc --noEmit`
Expected: no output (clean).

- [ ] **Step 4: Run the regression suite**

Run: `cd web && npx vitest run src/utils/securityModes.test.ts --no-coverage`
Expected: `14 passed | 1 skipped` or similar — all duress tests green.

- [ ] **Step 5: Commit**

```bash
cd /home/pwd-vm/PWDnow/web
git add src/pages/Login.tsx
git commit -m "fix(login): await recordFailedLoginAttempt so wipe only fires at threshold"
```

---

## Task 3: Split login-hints rate limit from the destructive login limit

**Files:**
- Modify: `web/auth.js` — add a separate counter for the cheap email-hints lookup.

- [ ] **Step 1: Locate the existing limiter declarations**

Read `web/auth.js` around lines 85-118. Confirm `_loginRateLimiter`, `LOGIN_MAX_PER_WINDOW = 10`, `LOGIN_WINDOW_MS = 5 * 60 * 1000`, `checkLoginRate(ip)` exist.

- [ ] **Step 2: Add a separate hints limiter**

Insert these declarations directly below the `checkLoginRate` function (around line 118), before any other definitions:

```js
// Email-step hints lookup is read-only (no Argon2id, no password verification)
// so it can tolerate a much higher rate. Keeping it on the same 10/5-min
// counter as `/api/auth/login` was making users hit 429 after a handful of
// retried email entries — and pre-empting the wrong-password UX feedback.
const _hintsRateLimiter        = new Map();
const HINTS_MAX_PER_WINDOW     = 60;
const HINTS_WINDOW_MS          = 5 * 60 * 1000;

function checkHintsRate(ip) {
  const now = Date.now();
  let e = _hintsRateLimiter.get(ip);
  if (!e || now > e.resetAt) {
    e = { count: 0, resetAt: now + HINTS_WINDOW_MS };
    _hintsRateLimiter.set(ip, e);
    enforceMapCap(_hintsRateLimiter);
  }
  const updated = { ...e, count: e.count + 1 };
  _hintsRateLimiter.set(ip, updated);
  return updated.count <= HINTS_MAX_PER_WINDOW;
}
```

- [ ] **Step 3: Include the new map in the periodic cap enforcement loop**

Locate the existing `for (const map of [_loginRateLimiter, _registerRateLimiter, _emergencyRateLimiter])` loop (around line 190). Append `_hintsRateLimiter` to the array:

```js
  for (const map of [_loginRateLimiter, _registerRateLimiter, _emergencyRateLimiter, _hintsRateLimiter]) {
```

- [ ] **Step 4: Point `/api/auth/login-hints` at the new limiter**

Locate the unauthenticated branch of `app.post('/api/auth/login-hints', ...)` (around `auth.js:1022`):

```js
    if (!checkLoginRate(getClientIp(req))) {
      return res.status(429).json({ error: 'too_many_requests' });
    }
```

Replace with:

```js
    if (!checkHintsRate(getClientIp(req))) {
      return res.status(429).json({ error: 'too_many_requests' });
    }
```

Leave `checkLoginRate` in place at `/api/auth/login` (~line 1081) and other destructive endpoints — those should remain strict.

- [ ] **Step 5: Smoke-test the endpoint**

Restart the dev server (if running) and verify the endpoint:

```bash
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
  curl -sk -o /dev/null -w "%{http_code}\n" \
    -X POST https://localhost:51234/api/auth/login-hints \
    -H "Content-Type: application/json" \
    -d '{"email":"e2e-test@pwdnow.local"}'
done
```

Expected: twelve consecutive `200`s (no 429 within the first 60 requests). With the prior limiter you would have seen 429s starting at request 11.

- [ ] **Step 6: Commit**

```bash
cd /home/pwd-vm/PWDnow
git add web/auth.js
git commit -m "fix(auth): separate rate-limit budget for /api/auth/login-hints"
```

---

## Task 4: E2E proof — wipe fires after exactly N, error renders before that

**Files:**
- Create: `web/e2e/duress-wipe-trigger.spec.ts`

- [ ] **Step 1: Write the failing test**

Create `web/e2e/duress-wipe-trigger.spec.ts` with this content:

```ts
/**
 * Verify the duress auto-wipe threshold:
 *   - First (maxAttempts - 1) wrong passwords show the error message and
 *     decrement the visible "remaining" counter.
 *   - The Nth wrong password triggers `wipeVaultData` + redirect.
 * Also verifies the error text is visible (regression for the missing `await`
 * that previously hid the message behind a redirect on every attempt).
 */
import { test, expect } from '@playwright/test';

const EMAIL = 'e2e-test@pwdnow.local';
const REAL_PASSWORD = 'E2eTestPassw0rd!1';
const WRONG_PASSWORD = 'definitely-not-the-password-xyz';
const DURESS_PASSWORD = 'DuressWipe123!';
const BASE_URL = 'https://localhost:51234';

test.use({ baseURL: BASE_URL, ignoreHTTPSErrors: true });

async function login(page: import('@playwright/test').Page, password: string) {
  await page.locator('input[type="email"]').fill(EMAIL);
  await page.getByRole('button', { name: /continue|next/i }).first().click().catch(() => {});
  await page.locator('input[type="password"]').waitFor({ timeout: 10000 });
  await page.locator('input[type="password"]').fill(password);
  await page.locator('button[type="submit"]').click();
}

test('wipe only fires after N wrong passwords, error visible before that', async ({ page }) => {
  // Step 1: log in with the real password and arm duress mode with maxAttempts=3.
  await page.goto('/login');
  await page.waitForLoadState('networkidle');
  await login(page, REAL_PASSWORD);
  await page.waitForURL(/\/(vault|dashboard|settings)/, { timeout: 30000 });

  await page.goto('/settings');
  await page.waitForLoadState('networkidle');
  const select = page.locator('select').filter({ has: page.locator('option', { hasText: 'failed attempt' }) }).first();
  await select.selectOption({ value: '3' });
  await page.getByRole('button', { name: /arm duress mode/i }).click();
  const pwInputs = page.locator('input[type="password"]');
  await pwInputs.first().fill(DURESS_PASSWORD);
  await page.getByRole('button', { name: /^next/i }).click();
  await pwInputs.nth(1).fill(DURESS_PASSWORD);
  await page.getByRole('button', { name: /^arm duress mode/i }).click();
  await page.waitForTimeout(8000); // Argon2id 256MiB/t=3

  // Step 2: logout.
  await page.evaluate(async () => {
    const csrf = document.cookie.match(/_pwd_csrf=([^;]*)/)?.[1] ?? '';
    if (csrf) await fetch('/api/auth/logout', { method: 'POST', headers: { 'X-CSRF-Token': csrf } });
  });
  await page.goto('/login');
  await page.waitForLoadState('networkidle');

  // Step 3: wrong password #1 — error must be visible, no redirect, counter = 2.
  await login(page, WRONG_PASSWORD);
  await page.waitForSelector('text=/invalid master password/i', { timeout: 10000 });
  expect(page.url()).toMatch(/\/login/);
  await expect(page.locator('text=/2 attempts? remaining/i')).toBeVisible();

  // Step 4: wrong password #2 — error visible, counter = 1.
  await page.locator('input[type="password"]').fill(WRONG_PASSWORD);
  await page.locator('button[type="submit"]').click();
  await page.waitForSelector('text=/1 attempts? remaining/i', { timeout: 10000 });

  // Step 5: wrong password #3 — wipe should fire (localStorage cleared, redirect).
  await page.locator('input[type="password"]').fill(WRONG_PASSWORD);
  await page.locator('button[type="submit"]').click();
  // Either the page reloads to /login (window.location.replace) or the URL
  // remains /login. Either way, the wipe path drops the keys.
  await page.waitForTimeout(3000);
  const localKeys = await page.evaluate(() => Object.keys(localStorage));
  expect(localKeys.length).toBeLessThanOrEqual(2); // theme + maybe one other; vault keys must be gone
});
```

- [ ] **Step 2: Create a one-off Playwright config (so we don't conflict with the running server)**

Create `web/playwright.duress.config.ts`:

```ts
import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './e2e',
  testMatch: 'duress-wipe-trigger.spec.ts',
  timeout: 180_000,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: 'https://localhost:51234',
    ignoreHTTPSErrors: true,
    launchOptions: {
      executablePath: '/usr/bin/brave-browser',
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    },
  },
});
```

- [ ] **Step 3: Run the E2E**

Run: `cd web && timeout 240 npx playwright test --config playwright.duress.config.ts`
Expected: PASS.

- [ ] **Step 4: Clean up the one-off config (do NOT keep it in tree)**

```bash
rm web/playwright.duress.config.ts
```

Keep `web/e2e/duress-wipe-trigger.spec.ts` — it should be picked up by the default `web/playwright.config.ts`.

- [ ] **Step 5: Commit**

```bash
cd /home/pwd-vm/PWDnow
git add web/e2e/duress-wipe-trigger.spec.ts
git commit -m "test(e2e): duress wipe fires only at threshold; error visible before"
```

---

## Task 5: Rebuild and verify on the live dev server

- [ ] **Step 1: Build**

```bash
cd /home/pwd-vm/PWDnow/web
npm run build
```

Expected: `✓ built in <Ns>` and `dist/sw.js`, `dist/workbox-*.js` generated.

- [ ] **Step 2: Restart the running Node server so it picks up `auth.js` changes**

```bash
kill $(pgrep -f 'node /home/pwd-vm/PWDnow/web/server.js') 2>/dev/null
sleep 2
cd /home/pwd-vm/PWDnow/web
nohup node server.js > /tmp/pwdnow-server.log 2>&1 &
sleep 4
curl -sk https://localhost:51234/api/setup-status
```

Expected: `{"completed":true}`.

- [ ] **Step 3: Manual smoke against the live server**

Confirm hints endpoint no longer 429s on the first dozen retries:

```bash
for i in $(seq 1 12); do
  curl -sk -o /dev/null -w "%{http_code}\n" \
    -X POST https://localhost:51234/api/auth/login-hints \
    -H "Content-Type: application/json" \
    -d '{"email":"e2e-test@pwdnow.local"}'
done
```

Expected: twelve `200`s.

---

## Self-Review Checklist

1. **Spec coverage:**
   - Wipe-on-Nth-attempt-not-on-first → Task 1 (unit) + Task 2 (fix) + Task 4 (e2e). ✓
   - Error message displays on wrong password → Task 2 fix (no longer pre-empted by redirect) + Task 4 assertion. ✓
   - 429 from `/api/auth/login-hints` → Task 3 (separate rate-limit budget). ✓

2. **Placeholder scan:** no `TBD`, no "add error handling", every step shows the exact code. ✓

3. **Type consistency:**
   - `recordFailedLoginAttempt` already returns `Promise<boolean>` (no signature change). Task 2 just adds `await`. ✓
   - `checkHintsRate` shape matches `checkLoginRate`. ✓
