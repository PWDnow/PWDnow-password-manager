import { test, chromium } from '@playwright/test';

const BASE = 'http://127.0.0.1:1234';
const EMAIL = 'wee.wa@gmail.com';
const PW = 'wee.wa@gmail.comAwee.wa@gmail.com';

test.setTimeout(180_000);

async function login(page: any) {
  await page.goto(`${BASE}/login`);
  await page.waitForLoadState('networkidle');
  await page.fill('input[type="email"]', EMAIL);
  await page.click('button[type="submit"]');
  await page.waitForTimeout(2000);
  const masterPwBtn = page.locator('button:has-text("Master Password")').first();
  if (await masterPwBtn.isVisible().catch(() => false)) await masterPwBtn.click();
  await page.waitForSelector('input[type="password"]', { timeout: 15000 });
  await page.fill('input[type="password"]', PW);
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/vault/, { timeout: 60000 });
  await page.waitForTimeout(2500);
}

test('repro: reload after folder creation', async () => {
  const browser = await chromium.launch({
    executablePath: '/usr/bin/brave-browser',
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  page.on('console', m => {
    console.log(`B[${m.type()}]:`, m.text().slice(0, 300));
  });

  await login(page);
  
  const ksBefore = await page.evaluate(() => sessionStorage.getItem('_pwd_ks'));
  console.log('KS BEFORE RELOAD:', ksBefore ? ksBefore.substring(0, 100) + '...' : 'null');

  await page.goto(`${BASE}/manage-folders`);
  await page.waitForTimeout(1200);
  
  const ksAfter = await page.evaluate(() => {
    const ks = sessionStorage.getItem('_pwd_ks');
    return ks ? Object.keys(JSON.parse(ks)).join(',') : 'null';
  });
  console.log('KS AFTER GOTO KEYS:', ksAfter);
  
  const folderName = `RELOAD_${Date.now()}`;
  await page.locator('button:has-text("Create Folder")').first().click();
  await page.waitForTimeout(500);
  const nameInput = page.locator('input[placeholder*="Personal" i]').first();
  await nameInput.fill(folderName);
  await page.locator('button:has-text("Create Folder")').last().click();
  await page.waitForTimeout(2500);
  console.log('After create, sidebar contains folder?', 
    (await page.locator('aside').first().innerText()).includes(folderName));

  const ksAfterCreate = await page.evaluate(() => {
    const ks = sessionStorage.getItem('_pwd_ks');
    if (!ks) return 'null';
    const parsed = JSON.parse(ks);
    return {
      v1: parsed.localKeyV1 ? Object.values(parsed.localKeyV1).slice(0,10).join(',') : 'null',
      v2: parsed.localKeyV2 ? Object.values(parsed.localKeyV2).slice(0,10).join(',') : 'null',
    };
  });
  console.log('KEYS BEFORE RELOAD:', ksAfterCreate);

  // Now reload
  await page.reload();
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(5000);
  
  const ksAfterReload = await page.evaluate(() => {
    const ks = sessionStorage.getItem('_pwd_ks');
    if (!ks) return 'null';
    const parsed = JSON.parse(ks);
    return {
      v1: parsed.localKeyV1 ? Object.values(parsed.localKeyV1).slice(0,10).join(',') : 'null',
      v2: parsed.localKeyV2 ? Object.values(parsed.localKeyV2).slice(0,10).join(',') : 'null',
    };
  });
  console.log('KEYS AFTER RELOAD:', ksAfterReload);
  
  await page.screenshot({ path: 'test-results/reload-after.png', fullPage: true });
  const sidebarAfter = await page.locator('aside').first().innerText();
  console.log('SIDEBAR AFTER RELOAD:', sidebarAfter.replace(/\n/g, ' | '));
  console.log('Survived reload?', sidebarAfter.includes(folderName));

  // Now logout and re-login
  await page.click('button:has-text("Logout")');
  await page.waitForURL(/\/login/, { timeout: 10000 });
  await page.waitForTimeout(1000);
  await login(page);
  await page.waitForTimeout(4000);
  await page.screenshot({ path: 'test-results/relogin-after.png', fullPage: true });
  const sidebarRelogin = await page.locator('aside').first().innerText();
  console.log('SIDEBAR AFTER RELOGIN:', sidebarRelogin.replace(/\n/g, ' | '));
  console.log('Survived re-login?', sidebarRelogin.includes(folderName));

  // Also check via direct API + decrypt attempt
  const apiCheck = await page.evaluate(async () => {
    const r = await fetch('/api/vault/folders', { credentials: 'same-origin' });
    return { status: r.status, body: (await r.text()).slice(0, 200) };
  });
  console.log('API folders content:', JSON.stringify(apiCheck));

  await browser.close();
});
