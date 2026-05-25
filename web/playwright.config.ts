import { defineConfig } from '@playwright/test';

// @race tagged specs cover concurrent-fetch regressions from the 2026-05-21
// audit. They are excluded from the default test run because they intentionally
// fire bursts of parallel requests that ~double the wall-clock time. Run
// them via `npm run test:race` before each release or after touching any
// auth.js / securityModes.ts code path that interacts with users.enc.
const RACE_GREP = /@race/;

export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  fullyParallel: false,
  retries: 1,
  reporter: 'list',
  grepInvert: process.env.PLAYWRIGHT_INCLUDE_RACE ? undefined : RACE_GREP,
  use: {
    baseURL: 'http://localhost:1234',
    viewport: { width: 1280, height: 720 },
    ignoreHTTPSErrors: true,
    launchOptions: {
      executablePath: '/usr/bin/brave-browser',
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--enable-features=WebAuthenticationTouchId',
        '--enable-experimental-web-platform-features',
      ],
    },
  },
  projects: [
    { name: 'brave', use: {} },
  ],
  webServer: {
    command: 'node --expose-gc server.js',
    url: 'https://127.0.0.1:51234/api/setup-status',
    ignoreHTTPSErrors: true,
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000,
  },
});
