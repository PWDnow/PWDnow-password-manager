import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch({
    executablePath: '/usr/bin/brave-browser',
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const context = await browser.newContext();
  await context.addCookies([{
    name: '_pwd_csrf',
    value: 'fake_csrf_token',
    domain: 'localhost',
    path: '/',
  }]);
  
  const page = await context.newPage();
  
  page.on('pageerror', err => {
    console.log(`[Browser PageError] ${err.message}`);
  });
  page.on('console', msg => {
    if (msg.type() === 'error' || msg.type() === 'warning') {
      console.log(`[Browser ${msg.type()}] ${msg.text()}`);
    }
  });

  console.log('Navigating to localhost:1234/login...');
  await page.goto('http://localhost:1234/login', { waitUntil: 'load' });
  await page.waitForTimeout(3000);

  // simulate submitting email
  console.log('Submitting email...');
  await page.fill('input[type="text"]', 'wang@gmail.com');
  await page.click('button[type="submit"]');

  await page.waitForTimeout(3000);

  await browser.close();
  console.log('Done');
})();
