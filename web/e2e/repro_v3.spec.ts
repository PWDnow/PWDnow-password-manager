import { test, expect, chromium } from '@playwright/test';

test('repro folder disappearance with full logging', async () => {
  const browser = await chromium.launch({ executablePath: '/usr/bin/brave-browser' });
  const page = await browser.newPage();
  
  page.on('console', msg => console.log(`BROWSER [${msg.type()}]: ${msg.text()}`));
  page.on('request', request => {
    if (request.url().includes('/api/vault/')) {
      console.log(`REQUEST: ${request.method()} ${request.url()}`);
    }
  });
  page.on('response', response => {
    if (response.url().includes('/api/vault/')) {
      console.log(`RESPONSE: ${response.status()} ${response.url()}`);
    }
  });

  console.log('1. Navigating to login');
  await page.goto('http://localhost:1234/login');
  
  console.log('2. Entering email');
  await page.fill('#email', 'wang@gmail.com');
  await page.click('button[type="submit"]');
  
  console.log('3. Waiting for password field');
  await page.waitForSelector('#password', { timeout: 10000 });
  await page.fill('#password', 'name');
  await page.click('button[type="submit"]');
  
  console.log('4. Waiting for vault');
  await page.waitForURL(/\/vault/, { timeout: 10000 });
  console.log('Logged in.');
  await page.waitForTimeout(2000);

  // Create folder
  console.log('5. Creating folder');
  await page.click('button[aria-label="Manage Folders"]');
  await page.waitForURL(/\/manage-folders/);
  
  const folderName = 'DEBUG_' + Date.now();
  await page.click('button:has-text("Create New Folder")');
  await page.fill('input[placeholder="e.g. Work, Personal, Banking"]', folderName);
  await page.click('button:has-text("Create Folder")');
  
  await page.waitForSelector(`text=${folderName}`);
  console.log(`Folder "${folderName}" created.`);

  // Wait for sync logs
  await page.waitForTimeout(5000);

  // REFRESH
  console.log('6. Refreshing');
  await page.reload();
  await page.waitForURL(/\/vault/);
  await page.waitForTimeout(5000);
  
  const sidebar = await page.innerText('aside');
  if (sidebar.includes(folderName)) {
    console.log('SUCCESS: Folder survived refresh');
  } else {
    console.log('FAILURE: Folder disappeared after refresh');
  }

  await browser.close();
});
