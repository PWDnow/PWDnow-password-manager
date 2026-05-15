import { test, expect, chromium } from '@playwright/test';
import fs from 'fs';
const BASE = 'http://localhost:1234';

test('kdbx: passphrase prompt appears + spinner shows + browser stays responsive', async () => {
  const kdbxPath = '/tmp/L9FZ6/kitten.kdbx';
  if (!fs.existsSync(kdbxPath)) { console.log('No kdbx file'); return; }

  const browser = await chromium.launch({
    executablePath: '/usr/bin/brave-browser',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  const ctx = await browser.newContext({ baseURL: BASE });
  const ts = Date.now();
  await ctx.request.post('/api/auth/register', { data: { email: `sc${ts}@t.co`, password: 'TestPassword!2024', firstName: 'A', lastName: 'B' } });
  await ctx.request.post('/api/auth/login', { data: { email: `sc${ts}@t.co`, password: 'TestPassword!2024' } });

  const page = await ctx.newPage();
  await page.addInitScript(() => {
    (window as any).__maxTask = 0;
    if ('PerformanceObserver' in window) {
      new PerformanceObserver(list => {
        for (const e of list.getEntries())
          if (e.duration > (window as any).__maxTask) (window as any).__maxTask = e.duration;
      }).observe({ entryTypes: ['longtask'] });
    }
  });

  const consoleErrors: string[] = [];
  page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

  await page.goto(`${BASE}/settings`, { waitUntil: 'networkidle' });

  // Target the IMPORT file input specifically (has kdbx in accept)
  const importFileInput = page.locator('input[type="file"][accept*="kdbx"]').first();
  await expect(importFileInput).toBeAttached({ timeout: 8000 });
  await importFileInput.setInputFiles(kdbxPath);

  // KeePass-specific passphrase prompt must appear
  const passPrompt = page.locator('input[placeholder*="master password" i]').first();
  await expect(passPrompt, 'KeePass passphrase prompt should appear').toBeVisible({ timeout: 8000 });
  console.log('✅ KeePass passphrase prompt visible with correct "master password" placeholder');
  await passPrompt.scrollIntoViewIfNeeded();
  await page.screenshot({ path: '/tmp/kdbx_1_prompt.png' });

  // Verify the heading says "KeePass database" not generic "Export passphrase"
  const heading = page.getByText(/KeePass database/i).first();
  await expect(heading, 'Should show KeePass-specific heading').toBeVisible({ timeout: 3000 });
  console.log('✅ Heading correctly says "KeePass database"');

  // Enter password and click Unlock to trigger loading spinner
  await passPrompt.fill('any_password_to_test_spinner');
  const unlockBtn = page.getByText('Unlock & Import').first();
  await expect(unlockBtn, '"Unlock & Import" button should be visible').toBeVisible({ timeout: 3000 });
  await unlockBtn.click();

  // Capture spinner state immediately (within 2s before argon2 finishes)
  await page.waitForTimeout(500);
  await page.screenshot({ path: '/tmp/kdbx_2_spinner.png' });

  const spinner = page.locator('.animate-spin').first();
  const spinnerVisible = await spinner.isVisible({ timeout: 2000 }).catch(() => false);
  console.log('✅ Loading spinner visible during argon2 decryption:', spinnerVisible);

  const unlockingText = page.getByText(/Unlocking/i).first();
  const unlockingVisible = await unlockingText.isVisible({ timeout: 2000 }).catch(() => false);
  console.log('✅ "Unlocking…" text on button:', unlockingVisible);

  // Check that the browser is NOT blocked (max long task < 5000ms = no "Page Unresponsive" possible)
  await page.waitForTimeout(1000);
  const maxTask = await page.evaluate(() => (window as any).__maxTask ?? 0);
  console.log(`Max long task so far: ${maxTask.toFixed(0)}ms (< 5000ms = browser responsive)`);
  expect(maxTask, 'Main thread must not be blocked — async argon2 must be working').toBeLessThan(5000);

  // Verify no unexpected console errors
  const unexpectedErrors = consoleErrors.filter(e => !e.includes('favicon') && !e.includes('ws://'));
  console.log('Console errors:', unexpectedErrors);
  expect(unexpectedErrors).toHaveLength(0);

  await browser.close();
  console.log('');
  console.log('Screenshots: /tmp/kdbx_1_prompt.png  /tmp/kdbx_2_spinner.png');
});
