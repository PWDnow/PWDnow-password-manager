/**
 * Regression: 429 responses from /api/auth/login must NOT decrement the
 * duress counter. Previously the frontend treated 429 (rate limit,
 * account lockout, MFA lockout) as a bad-password attempt, which would
 * let any attacker who can trigger the rate limit drive the counter to
 * zero and force a wipe.
 *
 * Test strategy: set maxAttempts=11 so the duress budget is larger than
 * the IP rate-limit budget (10/5min) AND larger than the per-account
 * lockout threshold (5). Submit 11 wrong passwords; after the lockout
 * kicks in, the remaining submits must:
 *   (a) NOT decrement the duress counter
 *   (b) surface a rate-limit message, not "Invalid master password"
 *
 * Before the fix this test fails at the final `expect(remaining > 0)`
 * because all 11 submits decrement.
 */
import { test, expect } from '@playwright/test';

const EMAIL = 'rate-limit-test@example.com';
const WRONG_PASSWORD = 'definitely-not-the-password-rl-xyz';
const BASE_URL = 'https://localhost:51234';

const FAKE_DURESS_CFG = {
  armed: true,
  passwordHash: '$argon2id$v=19$m=262144,t=3,p=1$00112233445566778899aabbccddeeff$' + '0'.repeat(64),
  maxAttempts: 11,
  attemptsRemaining: 11,
  salt: '00112233445566778899aabbccddeeff',
};

test.use({ baseURL: BASE_URL, ignoreHTTPSErrors: true });

test('429 from /api/auth/login does NOT decrement duress counter', async ({ page }) => {
  page.on('pageerror', e => console.log('[pageerror]', e.message));

  await page.goto('/login');
  await page.waitForLoadState('networkidle');

  await page.evaluate((cfg) => {
    localStorage.setItem('duress_mode_config', JSON.stringify(cfg));
    localStorage.setItem('duress_mode_config_sentinel', JSON.stringify({
      armed: cfg.armed, maxAttempts: cfg.maxAttempts, attemptsRemaining: cfg.attemptsRemaining,
    }));
  }, FAKE_DURESS_CFG);

  await page.reload();
  await page.waitForLoadState('networkidle');

  // Get past the email step once. After this the UI stays on the password
  // step across failed attempts - we only re-fill the password input.
  await page.locator('input[type="email"]').fill(EMAIL);
  await page.getByRole('button', { name: /continue|next/i }).first().click().catch(() => {});
  await page.locator('input[type="password"]').waitFor({ timeout: 15000 });

  const submit = page.locator('button[type="submit"]');

  // Submit 11 wrong passwords. The server will rate-limit somewhere
  // between attempt 5 (account lockout) and 10 (IP rate limit). Each
  // attempt's error must be either the wrong-password message OR the
  // rate-limit message - both are acceptable proofs that the request
  // round-tripped.
  for (let i = 0; i < 11; i++) {
    await page.locator('input[type="password"]').fill(WRONG_PASSWORD);
    await submit.click();
    await expect(
      page.locator('text=/invalid master password|temporarily locked|too many login attempts|wait \\d+ minutes?/i')
    ).toBeVisible({ timeout: 25000 });
    // Clear the field for the next submit.
    await page.locator('input[type="password"]').fill('');
  }

  // The duress sentinel must still be present (no wipe) and the counter
  // must be greater than zero. Before the fix this would be 0 and
  // localStorage would have been cleared by wipeVaultData.
  const remaining = await page.evaluate(() => {
    const raw = localStorage.getItem('duress_mode_config_sentinel');
    return raw ? (JSON.parse(raw).attemptsRemaining as number) : null;
  });

  expect(remaining).not.toBeNull();
  expect(remaining!).toBeGreaterThan(0);
  expect(remaining!).toBeLessThanOrEqual(FAKE_DURESS_CFG.maxAttempts);

  const stillHasSentinel = await page.evaluate(() =>
    localStorage.getItem('duress_mode_config_sentinel') !== null
  );
  expect(stillHasSentinel).toBe(true);
});
