import { test, expect, chromium } from '@playwright/test';

test('repro folder disappearance', async () => {
  const browser = await chromium.launch({ executablePath: '/usr/bin/brave-browser' });
  const page = await browser.newPage();
  
  page.on('console', msg => console.log(`BROWSER: ${msg.text()}`));

  console.log('1. Navigating to login');
  await page.goto('http://localhost:1234/login');
  
  console.log('2. Entering email');
  await page.fill('#email', 'wang@gmail.com');
  await page.click('button[type="submit"]');
  
  console.log('3. Waiting for password field');
  try {
    await page.waitForSelector('#password', { timeout: 10000 });
  } catch (e) {
    console.log('Password field did not appear. Current URL:', page.url());
    const html = await page.content();
    console.log('HTML content:', html);
    throw e;
  }
  
  await page.fill('#password', 'name');
  await page.click('button[type="submit"]');
  
  console.log('4. Waiting for vault');
  await page.waitForURL(/\/vault/, { timeout: 10000 });
  console.log('Logged in.');

  // Create folder
  await page.click('button[aria-label="Manage Folders"]');
  await page.waitForURL(/\/manage-folders/);
  
  const folderName = 'AUTO_' + Date.now();
  await page.click('button:has-text("Create New Folder")');
  await page.fill('input[placeholder="e.g. Work, Personal, Banking"]', folderName);
  await page.click('button:has-text("Create Folder")');
  
  await page.waitForSelector(`text=${folderName}`);
  console.log('Folder created.');

  // REFRESH
  console.log('5. Refreshing');
  await page.reload();
  await page.waitForURL(/\/vault/);
  await page.waitForTimeout(3000);
  
  const sidebar = await page.innerText('aside');
  if (sidebar.includes(folderName)) {
    console.log('SUCCESS: Folder survived refresh');
  } else {
    console.log('FAILURE: Folder disappeared after refresh');
    // Log localStorage
    const ls = await page.evaluate(() => JSON.stringify(localStorage));
    console.log('LocalStorage:', ls);
  }

  await browser.close();
});
