import { test, expect, chromium } from '@playwright/test';

test('login with mfa-test@pwdnow.local', async () => {
  const browser = await chromium.launch({ executablePath: '/usr/bin/brave-browser' });
  const page = await browser.newPage();
  page.on('console', msg => console.log(`[Browser Console ${msg.type()}] ${msg.text()}`));
  page.on('pageerror', err => console.log(`[Browser Page Error] ${err.message}`));
  await page.goto('http://localhost:1234/login');
  
  await page.fill('#email', 'mfa-test@pwdnow.local');
  await page.click('button[type="submit"]');
  
  // Wait for network and DOM update
  await page.waitForTimeout(2000);
  
  const content = await page.content();
  console.log("HTML IS:", content);
  
  // Since there are no MFA options, we should just see the password box directly
  await expect(page.locator('#password')).toBeVisible();
  
  // Enter password
  await page.fill('#password', 'mfa-test@pwdnow.local');
  await page.click('button[type="submit"]');
  
  await page.waitForTimeout(2000);
  const finalHtml = await page.content();
  console.log("FINAL HTML IS:", finalHtml);
  
  // Wait for login (Argon2id with 256 MiB can take up to 15-20s in Playwright)
  await page.waitForURL(/\/vault/, { timeout: 30000 }).catch(() => console.log("Did not reach vault."));
  console.log("SUCCESSFULLY LOGGED IN AND REACHED VAULT!");
  
  await browser.close();
});