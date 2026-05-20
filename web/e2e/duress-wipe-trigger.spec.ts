/**
 * Verify the duress auto-wipe threshold:
 *   - First (maxAttempts - 1) wrong passwords show the error message and
 *     decrement the visible "remaining" counter.
 *   - The Nth wrong password triggers `wipeVaultData` + redirect.
 *
 * Also regression-tests the bug where Login.tsx called recordFailedLoginAttempt
 * without await, making `shouldWipe` a (truthy) Promise and pre-empting the
 * `setError(...)` rendering on every attempt.
 *
 * To keep runtime under a minute we skip the real Argon2id arm step and
 * inject the duress sentinel directly. The wrong password we send does not
 * match the (bogus) stored PHC, so `checkIsDuressPassword` returns false and
 * the failure path under test runs.
 */
import { test, expect } from '@playwright/test';

const EMAIL = 'wee.wa@gmail.com';
const WRONG_PASSWORD = 'definitely-not-the-password-xyz';
const BASE_URL = 'https://localhost:51234';

const FAKE_DURESS_CFG = {
  armed: true,
  passwordHash: '$argon2id$v=19$m=262144,t=3,p=1$00112233445566778899aabbccddeeff$' +
    '0'.repeat(64),
  maxAttempts: 3,
  attemptsRemaining: 3,
  salt: '00112233445566778899aabbccddeeff',
};

test.use({ baseURL: BASE_URL, ignoreHTTPSErrors: true });

test('wipe only fires after N wrong passwords; error visible before threshold', async ({ page }) => {
  page.on('pageerror', e => console.log('[pageerror]', e.message));

  // Visit /login so the right origin owns the localStorage we inject.
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
  // step across failed attempts — we only re-fill the password input.
  await page.locator('input[type="email"]').fill(EMAIL);
  await page.getByRole('button', { name: /continue|next/i }).first().click().catch(() => {});
  await page.locator('input[type="password"]').waitFor({ timeout: 15000 });

  const submit = page.locator('button[type="submit"]');

  // Attempt #1 — error must be visible, URL stays /login, counter shows 2.
  await page.locator('input[type="password"]').fill(WRONG_PASSWORD);
  await submit.click();
  await expect(page.locator('text=/invalid master password/i')).toBeVisible({ timeout: 15000 });
  expect(page.url()).toMatch(/\/login/);
  await expect(page.locator('text=/2\\s+attempts?\\s+remaining/i')).toBeVisible({ timeout: 5000 });

  // Attempt #2 — counter ticks to 1.
  await page.locator('input[type="password"]').fill(WRONG_PASSWORD);
  await submit.click();
  await expect(page.locator('text=/1\\s+attempts?\\s+remaining/i')).toBeVisible({ timeout: 15000 });

  // Attempt #3 — wipe should fire (localStorage emptied, redirect).
  // Each attempt runs Argon2id (256 MiB / t=3) inside the duress intercept
  // even though the wrong password is not the duress password, so allow
  // ~10s before checking the post-wipe localStorage state.
  await page.locator('input[type="password"]').fill(WRONG_PASSWORD);
  await submit.click();
  // Poll for the wipe condition: at the end of the wipe path localStorage
  // is cleared and overwritten before location.replace runs.
  await expect.poll(
    async () => (await page.evaluate(() => Object.keys(localStorage))).includes('duress_mode_config_sentinel'),
    { timeout: 20000, intervals: [500] },
  ).toBe(false);
  const lsKeys = await page.evaluate(() => Object.keys(localStorage));
  expect(lsKeys).not.toContain('duress_mode_config');
  expect(lsKeys).not.toContain('duress_mode_config_sentinel');
});
