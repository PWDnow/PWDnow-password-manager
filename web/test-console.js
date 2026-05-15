import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch({
    executablePath: '/usr/bin/brave-browser',
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu'
    ]
  });
  const page = await browser.newPage();
  
  page.on('console', msg => {
    if (msg.type() === 'error' || msg.type() === 'warning') {
      console.log(`[Browser ${msg.type()}] ${msg.text()}`);
    }
  });
  
  page.on('pageerror', error => {
    console.log(`[Browser PageError] ${error.message}`);
  });

  console.log('Navigating to localhost:1234/login...');
  await page.goto('http://localhost:1234/login', { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);
  
  // Try logging in to see more errors
  await page.fill('input[type="email"]', 'wee.wa@gmail.com');
  await page.fill('input[type="password"]', '123456');
  await page.click('button[type="submit"]');
  
  await page.waitForTimeout(3000);
  
  // Navigate to dashboard
  await page.goto('http://localhost:1234/', { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);

  await browser.close();
})();
