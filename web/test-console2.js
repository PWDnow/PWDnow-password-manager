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
  
  let errors = 0;
  page.on('console', msg => {
    if (msg.type() === 'error' || msg.type() === 'warning') {
      console.log(`[Browser ${msg.type()}] ${msg.text()}`);
      if (msg.type() === 'error') errors++;
    }
  });
  
  page.on('pageerror', error => {
    console.log(`[Browser PageError] ${error.message}`);
    errors++;
  });

  console.log('Navigating to localhost:1234/login...');
  await page.goto('http://localhost:1234/login', { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);
  
  console.log('Filling email...');
  await page.fill('#email', 'wee.wa@gmail.com');
  await page.click('button[type="submit"]');
  
  console.log('Waiting for password...');
  await page.waitForSelector('#password', { state: 'visible', timeout: 5000 });
  await page.fill('#password', '123456');
  await page.click('button[type="submit"]');
  
  console.log('Waiting for login to complete...');
  await page.waitForTimeout(5000);
  
  console.log('Navigating to dashboard...');
  await page.goto('http://localhost:1234/', { waitUntil: 'networkidle' });
  await page.waitForTimeout(3000);

  console.log(`Found ${errors} errors.`);
  await browser.close();
})();
