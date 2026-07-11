import { test, expect, type Page } from '@playwright/test';

const BASE_URL = 'http://localhost:1234';
const EMAIL    = 'e2e-test@pwdnow.local';
const PASSWORD = 'E2eTestPassw0rd!1';

async function login(page: Page) {
  await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle' });
  await page.locator('input[type="email"]').fill(EMAIL);
  await page.locator('button[type="submit"]').first().click();
  const mfaBtn = page.locator(
    'button:has-text("Password + Authenticator App"), button:has-text("Password + Email OTP")',
  ).first();
  if (await mfaBtn.isVisible({ timeout: 1500 }).catch(() => false)) await mfaBtn.click();
  await page.locator('input[type="password"]').fill(PASSWORD);
  await page.locator('button[type="submit"]').first().click();
  await page.waitForURL(/\/(vault|dashboard)/, { timeout: 15_000 });
}

async function csrfFromContext(page: Page): Promise<string> {
  return page.evaluate(() => {
    const m = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('_pwd_csrf='));
    return m ? decodeURIComponent(m.split('=')[1]) : '';
  });
}

/**
 * Regression for the bug reported 2026-05-19: enabling Travel Mode then
 * clearing cookies + cache (which wipes localStorage) and logging back in
 * resulted in "all data gone" + UI stuck on "Inactive". The server now
 * mirrors _tm_cfg so re-login can hydrate the state.
 */
test.describe('Travel Mode survives Clear-Site-Data', () => {
  test('server-side mirror restores state after localStorage wipe', async ({ page, context }) => {
    await login(page);

    const csrf = await csrfFromContext(page);
    expect(csrf).not.toEqual('');

    // Seed a Travel Mode config directly via the API (avoids brittle modal UX).
    const cfg = {
      active: true,
      passwordHash: 'regression-hash',
      hiddenFolderIds: ['regression-folder-id'],
      salt: 'regression-salt',
      ivHex: 'regression-iv',
      kdf_version: 2,
    };
    let putRes = await page.request.put(`${BASE_URL}/api/vault/travel-config`, {
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      data: { data: JSON.stringify(cfg) },
    });
    expect(putRes.status()).toBe(200);

    // Simulate "Clear cookies and cache": drop all client state.
    await context.clearCookies();
    await page.evaluate(() => { localStorage.clear(); sessionStorage.clear(); });

    // Log back in.
    await login(page);

    // Hit the new endpoint — the config must still be there.
    const getRes = await page.request.get(`${BASE_URL}/api/vault/travel-config`);
    expect(getRes.status()).toBe(200);
    const body = await getRes.json();
    expect(typeof body.data).toBe('string');
    expect(JSON.parse(body.data).active).toBe(true);
    expect(JSON.parse(body.data).hiddenFolderIds).toEqual(['regression-folder-id']);

    // The Settings UI loads the config asynchronously on mount — visit Settings
    // and confirm the "Active" badge is rendered.
    await page.goto(`${BASE_URL}/settings`, { waitUntil: 'networkidle' });
    // Wait for the async useEffect to settle.
    await expect(
      page.locator('text=/Travel Mode Active/i').first()
    ).toBeVisible({ timeout: 10_000 });

    // Clean up — disable Travel Mode via the API so the next test run starts clean.
    const csrfAfter = await csrfFromContext(page);
    await page.request.delete(`${BASE_URL}/api/vault/travel-config`, {
      headers: { 'X-CSRF-Token': csrfAfter },
    });
    await page.request.delete(`${BASE_URL}/api/vault/travel-vault`, {
      headers: { 'X-CSRF-Token': csrfAfter },
    });
  });
});
