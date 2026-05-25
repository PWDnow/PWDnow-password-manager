// @race — Duress counter regression test (C-1, C-1′ from race-condition.md).
//
// The duress mode wipes the user record after `maxAttempts` consecutive wrong
// passwords. Pre-fix, two concurrent wrong-password POSTs both loaded the
// same `duressFailureCount`, both incremented to N+1, both saveUsers()'d —
// net effect: the counter only advanced by 1 per BATCH of N concurrent
// attempts. With maxAttempts=3, a burst of 11 parallel attempts would NOT
// trigger the wipe.
//
// Post-fix (Batch 2), the entire counter R-M-W runs inside withUsersLock so
// each failure counts. This spec arms duress with maxAttempts=3, fires 11
// parallel wrong-password POSTs, and asserts that at least one response
// carries `duressWipe: true` — i.e., the wipe actually fired.

import { test, expect } from '@playwright/test';
import { parallelFetch, loginBody, countWhere } from './_concurrency';

const BASE = 'http://localhost:1234';

test.describe.serial('@race duress counter under parallel wrong passwords', () => {
  let email: string;
  const password = 'Correct-Horse-Battery-Staple-42';
  const duressPwd = 'Duress-Battery-Staple-77';

  test('arm duress + parallel wrong passwords trigger wipe @race', async ({ page }) => {
    test.setTimeout(180_000);
    email = `race-duress-${Date.now()}@example.com`;

    // 1. Register a fresh user.
    const reg = await page.request.post(`${BASE}/api/auth/register`, {
      data: { email, password, firstName: 'Race', lastName: 'Test' },
      headers: { 'Content-Type': 'application/json' },
    });
    expect(reg.status()).toBe(200);

    // 2. Arm duress with maxAttempts=3 (server-side flag).
    const csrf = (await page.request.get(`${BASE}/api/auth/me`)).headers()['set-cookie'] || '';
    // The CSRF cookie is set on login; we use the cookie value from the registration response.
    // Simpler: log in via the page, then call the duress-enforce endpoint.
    await page.goto(`${BASE}/login`);
    await page.fill('input[type=email]', email);
    await page.click('button[type=submit]');
    await page.fill('input[type=password]', password);
    await page.click('button[type=submit]');
    await page.waitForURL(/\/(vault|dashboard)/, { timeout: 30_000 });

    // Read the CSRF token from cookies.
    const cookies = await page.context().cookies();
    const csrfCookie = cookies.find(c => c.name === '_pwd_csrf');
    expect(csrfCookie, 'CSRF cookie should be set after login').toBeTruthy();

    const armRes = await page.request.put(`${BASE}/api/vault/duress-enforce`, {
      data: { armed: true, maxAttempts: 3 },
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfCookie!.value },
    });
    expect(armRes.status(), `arm duress should return 200; got ${armRes.status()}`).toBe(200);

    // 3. Log out so we're in the unauthenticated state.
    await page.request.post(`${BASE}/api/auth/logout`, {
      headers: { 'X-CSRF-Token': csrfCookie!.value },
    });

    // 4. FIRE 11 PARALLEL WRONG-PASSWORD POSTs.
    // Pre-patch: the counter would advance by 1 (or 2-3 at most) — the wipe
    // would NEVER fire. Post-patch: each failure counts; the wipe fires by
    // attempt ≤4 and at least one response carries `duressWipe: true`.
    const results = await parallelFetch<{ ok?: boolean; duressWipe?: boolean; duressRemaining?: number; error?: string }>(
      11,
      (i) => ({
        url: `${BASE}/api/auth/login`,
        init: {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: loginBody(email, `WRONG-attempt-${i}`),
        },
      }),
    );

    // Every response must be 200 (the duress flow returns 200 + body).
    for (const r of results) {
      expect(r.status).toBe(200);
    }

    const wipes = countWhere(results, r => r.body?.duressWipe === true);
    expect(wipes, `expected at least one response with duressWipe=true; pre-patch this was 0`).toBeGreaterThanOrEqual(1);

    // 5. Subsequent login attempt must fail because the user record was wiped.
    const afterWipe = await page.request.post(`${BASE}/api/auth/login`, {
      data: { email, password, browser: 'race-test' },
      headers: { 'Content-Type': 'application/json' },
    });
    const afterWipeBody = await afterWipe.json().catch(() => ({}));
    // The server returns 200 with invalid_credentials for unknown users (timing-safe).
    expect(afterWipeBody.ok ?? false).toBe(false);
  });
});
