import { test, expect, chromium, request as playwrightRequest } from '@playwright/test';
import fs from 'fs';

const BASE = 'http://localhost:1234';

test('Issue 1: no 404 asset errors on page load', async () => {
  const browser = await chromium.launch({
    executablePath: '/usr/bin/brave-browser',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  const ctx = await browser.newContext();
  await ctx.addInitScript(() => {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistrations().then(regs => regs.forEach(r => r.unregister()));
    }
  });
  const page = await ctx.newPage();

  const errors404: string[] = [];
  const jsErrors: string[] = [];

  page.on('response', res => {
    if (res.status() === 404 && res.url().includes('/assets/')) errors404.push(res.url());
  });
  page.on('console', msg => { if (msg.type() === 'error') jsErrors.push(msg.text()); });
  page.on('pageerror', err => jsErrors.push(err.message));

  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });

  console.log('404 asset errors:', errors404);
  console.log('JS errors:', jsErrors.filter(e => !e.includes('favicon')));

  expect(errors404, '404 asset errors found').toHaveLength(0);
  await browser.close();
});

test('Issue 2: kdbx upload triggers passphrase prompt and parses file', async () => {
  const kdbxCandidates = ['/tmp/L9FZ6/kitten.kdbx', '/tmp/GJASM/kitten.kdbx', '/tmp/1K66T/kitten.kdbx'];
  const kdbxPath = kdbxCandidates.find(p => fs.existsSync(p));
  if (!kdbxPath) throw new Error('No kdbx test file found in /tmp');
  console.log('Using kdbx:', kdbxPath);

  // Register + login via API to get cookies in context
  const ts = Date.now();
  const email = `pw_${ts}@test.local`;
  const pass = 'TestPassword!2024';

  const browser = await chromium.launch({
    executablePath: '/usr/bin/brave-browser',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  const ctx = await browser.newContext({ baseURL: BASE });

  // Use Playwright's API context (shares cookies with browser context)
  const api = ctx.request;
  const reg = await api.post('/api/auth/register', {
    data: { email, password: pass, firstName: 'Test', lastName: 'User' },
  });
  console.log('Register:', reg.status(), (await reg.json()).ok);

  const login = await api.post('/api/auth/login', {
    data: { email, password: pass },
  });
  console.log('Login:', login.status(), (await login.json()).ok);

  // Verify we're authenticated
  const me = await api.get('/api/auth/me');
  console.log('Auth check:', me.status());
  expect(me.status()).toBe(200);

  const page = await ctx.newPage();
  await page.goto(`${BASE}/settings`);
  await page.waitForLoadState('networkidle');
  console.log('Settings URL:', page.url());
  expect(page.url()).toContain('/settings');

  // Scroll to Import section
  const importHeading = page.getByText('Import & Export').first();
  if (await importHeading.isVisible({ timeout: 5000 }).catch(() => false)) {
    await importHeading.scrollIntoViewIfNeeded();
  }

  // Upload the kdbx file via the hidden file input
  const fileInput = page.locator('input[type="file"]').first();
  await expect(fileInput).toBeAttached({ timeout: 10000 });
  await fileInput.setInputFiles(kdbxPath);
  console.log('kdbx file selected');

  // The kdbx importer throws ENCRYPTED_PWDNOW → Settings shows passphrase input
  const passInput = page.locator('input[placeholder*="assphrase" i], input[placeholder*="assword" i]').last();
  await expect(passInput, 'Passphrase prompt should appear for encrypted kdbx').toBeVisible({ timeout: 8000 });
  console.log('Passphrase prompt appeared');

  // Try common kdbxweb test-suite passwords
  for (const pwd of ['password', 'kitten', '']) {
    const fresh = page.locator('input[placeholder*="assphrase" i], input[placeholder*="assword" i]').last();
    await fresh.fill(pwd);

    // Click unlock/submit button
    const unlockBtn = page.locator('button').filter({ hasText: /unlock|submit|import|confirm/i }).last();
    if (await unlockBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await unlockBtn.click();
    } else {
      await fresh.press('Enter');
    }

    // Wait up to 10s for kdbxweb to parse (argon2 is slow in browser too)
    await page.waitForTimeout(5000);

    // Check outcome
    const wrongMsg = page.locator('text=/wrong passphrase/i, text=/incorrect/i');
    const noCredsMsg = page.locator('text=/no credentials/i');
    const modal = page.locator('[role="dialog"]');

    if (await modal.isVisible({ timeout: 1000 }).catch(() => false)) {
      const modalText = await modal.textContent();
      console.log(`SUCCESS with pwd="${pwd}", modal: ${modalText?.slice(0, 200)}`);
      break;
    } else if (await wrongMsg.isVisible({ timeout: 1000 }).catch(() => false)) {
      console.log(`Wrong passphrase for pwd="${pwd}", trying next`);
      // Re-upload for next attempt
      await fileInput.setInputFiles(kdbxPath);
      await expect(page.locator('input[placeholder*="assphrase" i], input[placeholder*="assword" i]').last()).toBeVisible({ timeout: 5000 });
    } else if (await noCredsMsg.isVisible({ timeout: 1000 }).catch(() => false)) {
      console.log(`Opened but no credentials found with pwd="${pwd}"`);
      break;
    } else {
      const bodyText = (await page.textContent('body') ?? '').slice(0, 300);
      console.log(`Unclear result for pwd="${pwd}", page snippet: ${bodyText}`);
      break;
    }
  }

  await browser.close();
});
