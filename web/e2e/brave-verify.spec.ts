import { test, expect, chromium } from '@playwright/test';

test('verify site loads in Brave without console errors', async () => {
  const browser = await chromium.launch({ 
    executablePath: '/usr/bin/brave-browser',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const context = await browser.newContext();
  const page = await context.newPage();

  const errors: string[] = [];
  page.on('console', msg => {
    if (msg.type() === 'error') errors.push(msg.text());
  });
  
  page.on('pageerror', err => {
    errors.push(err.message);
  });

  page.on('requestfailed', request => {
    errors.push(`Request failed: ${request.url()} (${request.failure()?.errorText})`);
  });

  // Navigate to login
  await page.goto('http://localhost:1234/login');
  
  // Wait for the main app to mount (root should have content)
  await page.waitForSelector('#root > main', { timeout: 10000 });

  // Verify no 404s or script errors
  if (errors.length > 0) {
    console.error("PAGE LOAD ERRORS DETECTED:", errors);
  }
  
  expect(errors.filter(e => !e.includes('favicon.ico')).length).toBe(0);
  
  const title = await page.title();
  console.log("Page title:", title);
  expect(title).toContain('Digital Sanctuary');

  await browser.close();
});
