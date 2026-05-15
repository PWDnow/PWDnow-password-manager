import { test, expect } from '@playwright/test';

const BASE_URL = 'http://localhost:1234';
const EMAIL    = 'wee.wa@gmail.com';
const PASSWORD = 'wee.wa@gmail.comAwee.wa@gmail.com';

test('Folder survives clear-site-data + re-login', async ({ page, context }) => {
  // ── Login
  await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle' });
  await page.locator('input[type="email"]').fill(EMAIL);
  await page.locator('button[type="submit"]').first().click();
  await page.locator('input[type="password"]').waitFor({ state: 'visible', timeout: 10_000 });
  await page.locator('input[type="password"]').fill(PASSWORD);
  await page.locator('button[type="submit"]').first().click();
  await page.waitForURL('**/vault**', { timeout: 30_000 });
  console.log('Logged in. URL:', page.url());

  // ── Create folder
  const folderName = `PersistTest_${Date.now()}`;
  await page.goto(`${BASE_URL}/manage-folders`);
  await page.waitForLoadState('networkidle');
  await page.locator('button:has-text("Create Folder")').first().click();
  const folderInput = page.locator('input[placeholder*="folder" i], input[placeholder*="e.g." i]').first();
  await folderInput.waitFor({ state: 'visible', timeout: 5_000 });
  await folderInput.fill(folderName);
  await page.locator('div.relative.w-full.max-w-2xl >> button:has-text("Create Folder")').click();
  await page.locator(`text=${folderName}`).first().waitFor({ state: 'visible', timeout: 15_000 });
  console.log(`✓ Folder "${folderName}" created`);

  // ── Wait a beat to ensure server PUT completes
  await page.waitForTimeout(1000);

  // ── Verify folder is on the server via direct API call
  const csrf = await page.evaluate(() =>
    document.cookie.split(';').find(c => c.trim().startsWith('_pwd_csrf='))?.split('=')[1] ?? ''
  );
  console.log('CSRF token present:', csrf ? 'yes' : 'NO — not in server mode!');

  const foldersResp = await page.evaluate(async () => {
    const r = await fetch('/api/vault/folders', { credentials: 'same-origin' });
    const j = await r.json().catch(() => null);
    return { status: r.status, hasData: !!(j && j.data) };
  });
  console.log('Server folders API:', foldersResp);

  // ── Clear all site data (localStorage, sessionStorage, cookies, cache)
  await context.clearCookies();
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
  console.log('Site data cleared');

  // ── Hard refresh
  await page.reload({ waitUntil: 'networkidle' });
  console.log('After reload, URL:', page.url());

  // ── Should redirect to login (no session)
  await page.waitForURL('**/login**', { timeout: 10_000 });
  console.log('Redirected to login ✓');

  // ── Log back in
  await page.locator('input[type="email"]').fill(EMAIL);
  await page.locator('button[type="submit"]').first().click();
  await page.locator('input[type="password"]').waitFor({ state: 'visible', timeout: 10_000 });
  await page.locator('input[type="password"]').fill(PASSWORD);
  await page.locator('button[type="submit"]').first().click();
  await page.waitForURL('**/vault**', { timeout: 30_000 });
  console.log('Logged back in. URL:', page.url());

  // ── Check folder still appears
  await page.goto(`${BASE_URL}/manage-folders`);
  await page.waitForLoadState('networkidle');
  const folderVisible = await page.locator(`text=${folderName}`).isVisible({ timeout: 10_000 }).catch(() => false);
  console.log(`Folder "${folderName}" visible after re-login:`, folderVisible);
  expect(folderVisible).toBe(true);

  // ── Cleanup: delete the test folder
  if (folderVisible) {
    const folderRow = page.locator('li, [class*="group"]', { hasText: folderName }).first();
    await folderRow.locator('button').last().click();
    await page.locator('button:has-text("Confirm Delete"), button:has-text("Delete Everything")').first().click();
    console.log('Test folder deleted');
  }
});
