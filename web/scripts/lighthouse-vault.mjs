// One-off perf audit script: logs into the running server with a real
// browser session, then runs Lighthouse against the authenticated /vault
// page. Not part of the build — run manually with:
//   node scripts/lighthouse-vault.mjs
import puppeteer from 'puppeteer-core';
import { launch } from 'chrome-launcher';
import lighthouse from 'lighthouse';
import { writeFileSync } from 'fs';

const BASE_URL = 'https://localhost:51234';
const EMAIL = process.env.LH_EMAIL;
const PASSWORD = process.env.LH_PASSWORD;
if (!EMAIL || !PASSWORD) {
  throw new Error('Set LH_EMAIL and LH_PASSWORD env vars to run this script.');
}

const chrome = await launch({
  chromePath: '/usr/bin/brave-browser',
  ignoreDefaultFlags: true,
  chromeFlags: [
    '--headless=new',
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--ignore-certificate-errors',
  ],
});

const browser = await puppeteer.connect({
  browserURL: `http://127.0.0.1:${chrome.port}`,
});
const page = (await browser.pages())[0] ?? await browser.newPage();

await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle0' });
await page.waitForSelector('input[type="email"]', { timeout: 15000 });
await page.type('input[type="email"]', EMAIL);
// Puppeteer's CSS engine doesn't support Playwright's `:has-text()` pseudo-class,
// so use a plain attribute selector — the email-step button is `button[type="submit"]`.
await page.locator('button[type="submit"]').click();
await page.waitForSelector('input[type="password"]', { timeout: 15000 });
await page.type('input[type="password"]', PASSWORD);
await Promise.all([
  page.waitForNavigation({ waitUntil: 'networkidle0', timeout: 30000 }).catch(() => {}),
  page.locator('button[type="submit"]').click().catch(() => {}),
]);
await page.waitForFunction('location.pathname.startsWith("/vault")', { timeout: 30000 }).catch(() => {});

console.log('Logged in, current URL:', page.url());

const result = await lighthouse(`${BASE_URL}/vault`, {
  port: chrome.port,
  output: 'json',
  logLevel: 'info',
  formFactor: 'desktop',
  screenEmulation: { disabled: true },
  throttling: {
    rttMs: 0,
    throughputKbps: 0,
    cpuSlowdownMultiplier: 1,
    requestLatencyMs: 0,
    downloadThroughputKbps: 0,
    uploadThroughputKbps: 0,
  },
  throttlingMethod: 'provided',
}, undefined, page);

writeFileSync('lighthouse-vault-report.json', result.report);

const cats = result.lhr.categories;
for (const key of Object.keys(cats)) {
  console.log(`${cats[key].title}: ${Math.round(cats[key].score * 100)}`);
}
const audits = result.lhr.audits;
console.log('FCP:', audits['first-contentful-paint'].displayValue);
console.log('LCP:', audits['largest-contentful-paint'].displayValue);
console.log('TBT:', audits['total-blocking-time'].displayValue);
console.log('CLS:', audits['cumulative-layout-shift'].displayValue);
console.log('SI :', audits['speed-index'].displayValue);

await browser.disconnect();
await chrome.kill();
