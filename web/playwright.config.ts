import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  fullyParallel: false,
  retries: 1,
  reporter: 'list',
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
    url: 'http://127.0.0.1:1234/api/setup-status',
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000,
  },
});
