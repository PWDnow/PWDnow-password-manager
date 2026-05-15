/**
 * E2E tests: TOTP timing, WebAuthn virtual authenticator, login flow.
 * Uses a dedicated test account (playwright-test@pwdnow.local / Playwright!1)
 * registered against the running server at http://localhost:3000.
 */

import { test, expect, BrowserContext, Page } from '@playwright/test';
import { TOTP } from 'totp-generator';
import { encode, decode } from '@msgpack/msgpack';

const BASE          = 'http://localhost:1234';
const TEST_EMAIL    = 'playwright-test@pwdnow.local';
const TEST_PASSWORD = 'Playwright!1';
// Well-known base32 secret for deterministic TOTP codes in tests.
const TOTP_SECRET   = 'JBSWY3DPEHPK3PXP';

// ─── helpers ──────────────────────────────────────────────────────────────────

async function loginWithPassword(page: Page) {
  await page.goto(`${BASE}/login`);
  await page.fill('#email', TEST_EMAIL);
  await page.click('button[type=submit]');

  // Click the TOTP method card if it appears (new UI flow)
  const totpCard = page.locator('button:has-text("Authenticator App")');
  if (await totpCard.isVisible()) {
    await totpCard.click();
  }

  await page.waitForSelector('#password', { timeout: 8_000 });
  await page.fill('#password', TEST_PASSWORD);
  await page.click('button[type=submit]');
}

/** Inject a plaintext MFA config + login hints into localStorage. */
async function injectTotpConfig(page: Page, enabled: boolean) {
  await page.evaluate(
    ({ enabled }) => {
      localStorage.setItem('_pwdn_login_hints', JSON.stringify({
        totp: enabled,
        emailOtp: false,
        passwordEnabled: !enabled,
      }));
    },
    { enabled },
  );

  await page.route('**/api/vault/mfa', route => {
    route.fulfill({
      status: 200,
      body: JSON.stringify({
        totp: { enabled, secret: TOTP_SECRET, enabledAt: Date.now() },
        webauthn: { enabled: false, credentials: [] },
        passkey:  { enabled: false, credentials: [] },
        platform: { enabled: false, credentials: [] },
        email:    { enabled: false },
        passwordLoginEnabled: !enabled, // false = always require TOTP when enabled
      })
    });
  });

  await page.route('**/api/auth/login-hints*', route => {
    route.fulfill({
      status: 200,
      body: JSON.stringify({
        hints: {
          totp: enabled,
          emailOtp: false,
          passwordEnabled: !enabled,
          webauthn: false,
          passwordlessEnabled: false
        }
      })
    });
  });
}

/**
 * Mock the daemon WebSocket so tests can control what `GetLoginHints` returns
 * without needing a real vault or physical hardware.
 *
 * Handles: Ping → Pong, GetLoginHints → LoginHints(opts), Unlock → Unlocked,
 * ListFido2Devices → Fido2Devices([fakePath]), RegisterFido2 → Created,
 * and any other command → Ok (so Settings/Vault pages don't crash).
 */
async function mockDaemonWs(page: Page, opts: {
  fido2_ids?: number[][];
  password_login_enabled?: boolean;
  totp_enabled?: boolean;
  email_otp_enabled?: boolean;
  fido2_devices?: string[];
} = {}) {
  const {
    fido2_ids           = [],
    password_login_enabled = true,
    totp_enabled        = false,
    email_otp_enabled   = false,
    fido2_devices       = [],
  } = opts;

  await page.routeWebSocket(/\/ws$/, ws => {
    ws.onMessage((raw: Buffer | string) => {
      const body = Buffer.isBuffer(raw) ? raw : Buffer.from(raw as string);
      let req: { cmd: string; payload?: Record<string, unknown> };
      try { req = decode(body) as typeof req; } catch { return; }

      let resp: unknown;
      switch (req.cmd) {
        case 'Ping':
          resp = { status: 'Pong' }; break;
        case 'GetLoginHints':
          resp = { status: 'LoginHints', data: { password_login_enabled, totp_enabled, email_otp_enabled, fido2_ids } }; break;
        case 'GetStatus':
          resp = { status: 'Status', data: { locked: false } }; break;
        case 'Unlock':
        case 'UnlockWithPasskey':
          resp = { status: 'Unlocked', data: { session_token: 'mock-session-token-abc123', wipe_ticket: [] } }; break;
        case 'Lock':
          resp = { status: 'Locked' }; break;
        case 'GetProfile':
          resp = { status: 'Profile', data: { first_name: 'Test', last_name: 'User', email: TEST_EMAIL } }; break;
        case 'ListFido2Devices':
          resp = { status: 'Fido2Devices', data: fido2_devices }; break;
        case 'RegisterFido2':
          resp = { status: 'Created', data: { id: 'mock-fido2-key-id-' + Date.now() } }; break;
        case 'ListFido2Keys':
          resp = { status: 'Fido2Keys', data: Buffer.from(JSON.stringify([])) }; break;
        case 'ListFolders':
          resp = { status: 'Folders', data: Buffer.from(JSON.stringify([])) }; break;
        case 'ListCredentials':
          resp = { status: 'Credentials', data: Buffer.from(JSON.stringify([])) }; break;
        case 'GetAssetHolder':
          resp = { status: 'AssetHolder', data: Buffer.from(JSON.stringify({ emails: [], phone_numbers: [], u2f_key_names: [] })) }; break;
        case 'GetVaultTotpStatus':
          resp = { status: 'VaultTotpStatus', data: { active: false } }; break;
        default:
          resp = { status: 'Ok' };
      }
      ws.send(Buffer.from(encode(resp)));
    });
  });
}

/** Add a virtual USB CTAP2 authenticator via CDP. */
async function addVirtualAuthenticator(context: BrowserContext) {
  // Get the first existing page (or create one) for the CDP session
  const pages = context.pages();
  const page = pages.length > 0 ? pages[0] : await context.newPage();
  const session = await context.newCDPSession(page);
  await session.send('WebAuthn.enable');
  const { authenticatorId } = await session.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'usb',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  });
  return { session, authenticatorId };
}

// ─── TOTP timing ──────────────────────────────────────────────────────────────

test.describe('TOTP timing', () => {
  test.skip('expired previous-period code is rejected', async ({ page }) => {
    // First: log in without TOTP so we get a session and local key in storage
    await page.goto(`${BASE}/login`);
    await page.evaluate(() => {
      localStorage.removeItem('mfa_config');
      localStorage.removeItem('_pwdn_login_hints');
    });

    await loginWithPassword(page);
    await expect(page).toHaveURL(/\/vault/, { timeout: 15_000 });

    // Now inject TOTP config (requires TOTP on next login)
    await injectTotpConfig(page, true);

    // Go back to login
    await page.goto(`${BASE}/login`);

    // Previous period code (expired ≥ 30 s ago)
    const prevTs = Date.now() - 35_000;
    const { otp: expiredCode } = await TOTP.generate(TOTP_SECRET, { timestamp: prevTs });

    // Wait for the login page to stabilize (either email, password, or method selection)
    await page.waitForSelector('#email, #password, button:has-text("Authenticator App")', { timeout: 8_000 });

    const loginTotpCard = page.locator('button:has-text("Authenticator App")');
    const emailInput = page.locator('#email');
    
    if (await emailInput.isVisible()) {
      await page.fill('#email', TEST_EMAIL);
      await page.click('button[type=submit]');
    }

    // Wait again in case the form is transitioning to the method card
    await page.waitForSelector('#password, button:has-text("Authenticator App")', { timeout: 8_000 }).catch(() => {});

    if (await loginTotpCard.isVisible()) {
      await loginTotpCard.click();
    }

    await page.waitForSelector('#password', { timeout: 8_000 });
    await page.fill('#password', TEST_PASSWORD);
    await page.click('button[type=submit]');

    // Should reach TOTP step
    await expect(page.locator('text=Two-Step Verification')).toBeVisible({ timeout: 10_000 });

    // Enter expired code
    const inputs = page.locator('input[inputmode="numeric"]');
    for (let i = 0; i < 6; i++) {
      await inputs.nth(i).fill(expiredCode[i]);
    }
    await page.locator('button:has-text("Verify")').click();

    // Must show error and NOT navigate to vault
    await expect(page.locator('text=Incorrect code')).toBeVisible({ timeout: 5_000 });
    expect(page.url()).not.toContain('/vault');

    console.log(`✓  Expired code "${expiredCode}" (from ${new Date(prevTs).toISOString()}) was correctly rejected`);
  });

  test('current-period code is accepted', async ({ page }) => {
    await page.goto(`${BASE}/login`);
    await page.evaluate(() => {
      localStorage.removeItem('mfa_config');
      localStorage.removeItem('_pwdn_login_hints');
    });

    await loginWithPassword(page);
    await expect(page).toHaveURL(/\/vault/, { timeout: 15_000 });

    await injectTotpConfig(page, true);
    
    // Clear cookies to simulate a logged-out state so we don't get auto-redirected to /vault
    await page.context().clearCookies();
    await page.goto(`${BASE}/login`);

    const { otp: validCode } = await TOTP.generate(TOTP_SECRET, { timestamp: Date.now() });

    // Wait for the login page to stabilize (either email, password, or method selection)
    await page.waitForSelector('#email, #password, button:has-text("Authenticator App")', { timeout: 8_000 });

    const loginTotpCard = page.locator('button:has-text("Authenticator App")');
    const emailInput = page.locator('#email');
    
    if (await emailInput.isVisible()) {
      await page.fill('#email', TEST_EMAIL);
      await page.click('button[type=submit]');
    }

    // Wait again in case the form is transitioning to the method card
    await page.waitForSelector('#password, button:has-text("Authenticator App")', { timeout: 8_000 }).catch(() => {});

    if (await loginTotpCard.isVisible()) {
      await loginTotpCard.click();
    }

    await page.waitForSelector('#password', { timeout: 8_000 });
    await page.fill('#password', TEST_PASSWORD);
    await page.click('button[type=submit]');

    await expect(page.locator('text=Two-Step Verification')).toBeVisible({ timeout: 10_000 });

    const inputs = page.locator('input[inputmode="numeric"]');
    for (let i = 0; i < 6; i++) {
      await inputs.nth(i).fill(validCode[i]);
    }
    await page.locator('button:has-text("Verify")').click();

    await expect(page).toHaveURL(/\/vault/, { timeout: 10_000 });
    console.log(`✓  Current code "${validCode}" accepted successfully`);
  });
});

// ─── WebAuthn virtual authenticator ───────────────────────────────────────────

test.describe('WebAuthn virtual authenticator', () => {
  test('security key registers and flow completes', async ({ context, page }) => {
    // Mock the daemon so daemon.listFido2Devices() returns a fake device path
    // and daemon.registerFido2() succeeds. This makes the test pass without
    // physical FIDO2 hardware.
    await mockDaemonWs(page, { fido2_devices: ['/dev/mock/yubikey0'] });
    const { session } = await addVirtualAuthenticator(context);

    await page.goto(`${BASE}/login`);
    await page.evaluate(() => {
      localStorage.removeItem('mfa_config');
      localStorage.removeItem('_pwdn_login_hints');
    });

    await loginWithPassword(page);
    await expect(page).toHaveURL(/\/vault/, { timeout: 15_000 });

    // Navigate to Settings via sidebar click (client-side nav keeps in-memory session token)
    await page.locator('button').filter({ hasText: /settings/i }).first().click();
    await expect(page).toHaveURL(/\/settings/, { timeout: 5_000 });

    // Find and click the Security Key card
    await page.locator('[class*="cursor-pointer"]').filter({ hasText: 'Security Key' }).first().click();

    // Modal should open with register UI
    await expect(page.locator('text=Register Security Key')).toBeVisible({ timeout: 6_000 });

    // Fill key name and register — daemon mock auto-approves
    await page.fill('input[type="text"]', 'Virtual Test Key');
    await page.locator('button:has-text("Register")').last().click();

    // Expect the success heading shown after WebAuthn registration
    await expect(page.getByRole('heading', { name: 'Key registered' })).toBeVisible({ timeout: 15_000 });
    console.log('✓  Security key registered via mocked daemon (no physical hardware required)');

    await session.detach();
  });
});

// ─── MFA config persists across page refresh ─────────────────────────────────

test.describe('MFA config persistence', () => {
  test.skip('MFA config survives a page refresh', async ({ page }) => {
    // Log in and inject a TOTP config (simulates the user adding an authenticator)
    await page.goto(`${BASE}/login`);
    await page.evaluate(() => {
      localStorage.removeItem('mfa_config');
      localStorage.removeItem('mfa_config_plain');
      localStorage.removeItem('_pwdn_login_hints');
    });

    await loginWithPassword(page);
    await expect(page).toHaveURL(/\/vault/, { timeout: 15_000 });

    // Inject MFA config (as saveMfaConfig would do)
    await page.evaluate((secret) => {
      const cfg = {
        totp: { enabled: true, secret, enabledAt: Date.now() },
        webauthn: { enabled: false, credentials: [] },
        passkey:  { enabled: false, credentials: [] },
        platform: { enabled: false, credentials: [] },
        email:    { enabled: false },
        passwordLoginEnabled: false,
      };
      // Simulate what saveMfaConfig() does: write both plain backup and primary
      localStorage.setItem('mfa_config_plain', JSON.stringify(cfg));
      localStorage.setItem('mfa_config', JSON.stringify(cfg));
      localStorage.setItem('_pwdn_login_hints', JSON.stringify({ totp: true, emailOtp: false, passwordEnabled: false }));
    }, TOTP_SECRET);

    // Hard refresh the page (simulates the user pressing F5)
    await page.reload();

    // After refresh the Settings page should still show TOTP as active
    await page.goto(`${BASE}/settings`);

    // The TOTP card should show "Active" — config was not lost
    const totpCard = page.locator('[class*="cursor-pointer"]').filter({ hasText: 'Authenticator App' }).first();
    await expect(totpCard.locator('text=Active')).toBeVisible({ timeout: 8_000 });

    await page.context().clearCookies();
    await page.goto(`${BASE}/login`);
    const { otp: code } = await TOTP.generate(TOTP_SECRET, { timestamp: Date.now() });
    // Wait for the login page to stabilize (either email, password, or method selection)
    await page.waitForSelector('#email, #password, button:has-text("Authenticator App")', { timeout: 8_000 });

    const loginTotpCard = page.locator('button:has-text("Authenticator App")');
    const emailInput = page.locator('#email');
    
    if (await emailInput.isVisible()) {
      await page.fill('#email', TEST_EMAIL);
      await page.click('button[type=submit]');
    }

    // Wait again in case the form is transitioning to the method card
    await page.waitForSelector('#password, button:has-text("Authenticator App")', { timeout: 8_000 }).catch(() => {});

    if (await loginTotpCard.isVisible()) {
      await loginTotpCard.click();
    }

    await page.waitForSelector('#password', { timeout: 8_000 });
    await page.fill('#password', TEST_PASSWORD);
    await page.click('button[type=submit]');
    await expect(page.locator('text=Two-Step Verification')).toBeVisible({ timeout: 10_000 });

    const inputs = page.locator('input[inputmode="numeric"]');
    for (let i = 0; i < 6; i++) await inputs.nth(i).fill(code[i]);
    await page.locator('button:has-text("Verify")').click();
    await expect(page).toHaveURL(/\/vault/, { timeout: 10_000 });

    console.log('✓  MFA config survived page refresh — TOTP still active and verified');
  });
});

// ─── Basic login (no MFA) ─────────────────────────────────────────────────────

test.describe('Password login', () => {
  test('correct password navigates to vault', async ({ page }) => {
    await page.goto(`${BASE}/login`);
    await page.evaluate(() => {
      localStorage.removeItem('mfa_config');
      localStorage.removeItem('_pwdn_login_hints');
    });

    await loginWithPassword(page);
    await expect(page).toHaveURL(/\/vault/, { timeout: 15_000 });
    console.log('✓  Password login successful');
  });

  test('wrong password shows error', async ({ page }) => {
    await page.goto(`${BASE}/login`);
    // Wait for the login page to stabilize (either email, password, or method selection)
    await page.waitForSelector('#email, #password, button:has-text("Authenticator App")', { timeout: 8_000 });

    const loginTotpCard = page.locator('button:has-text("Authenticator App")');
    const emailInput = page.locator('#email');
    
    if (await emailInput.isVisible()) {
      await page.fill('#email', TEST_EMAIL);
      await page.click('button[type=submit]');
    }

    // Wait again in case the form is transitioning to the method card
    await page.waitForSelector('#password, button:has-text("Authenticator App")', { timeout: 8_000 }).catch(() => {});

    if (await loginTotpCard.isVisible()) {
      await loginTotpCard.click();
    }

    await page.waitForSelector('#password', { timeout: 8_000 });
    await page.fill('#password', 'wrong-password');
    await page.click('button[type=submit]');

    await expect(page.locator('[role=alert]')).toBeVisible({ timeout: 8_000 });
    expect(page.url()).not.toContain('/vault');
    console.log('✓  Wrong password correctly rejected');
  });
});

// ─── Login Methods UI ─────────────────────────────────────────────────────────
// These tests mock the daemon WebSocket so GetLoginHints returns controlled
// hints regardless of what is stored in the real vault on disk.

test.describe('Login Methods UI', () => {
  test('Security Key card is visible when webauthn hint is present', async ({ page }) => {
    // Daemon returns a non-empty fido2_ids list → hasWebAuthnHint = true
    await mockDaemonWs(page, {
      fido2_ids: [[0x01, 0x02, 0x03, 0x04]],
      password_login_enabled: true,
    });

    await page.goto(`${BASE}/login`);
    await page.fill('#email', TEST_EMAIL);
    await page.click('button[type=submit]');
    await page.waitForTimeout(1000);

    await expect(page.locator('button:has-text("Security Key (YubiKey)")')).toBeVisible({ timeout: 5000 });
    // Password field should also be visible (password_login_enabled = true)
    await expect(page.locator('#password')).toBeVisible();
    console.log('✓  Security Key card visible; password field also present');
  });

  test('Password form is hidden in passwordless mode', async ({ page }) => {
    // Daemon returns password_login_enabled = false + non-empty fido2_ids
    await mockDaemonWs(page, {
      fido2_ids: [[0x01, 0x02, 0x03, 0x04]],
      password_login_enabled: false,
    });

    await page.goto(`${BASE}/login`);
    await page.fill('#email', TEST_EMAIL);
    await page.click('button[type=submit]');
    await page.waitForTimeout(1000);

    await expect(page.locator('button:has-text("Security Key (YubiKey)")')).toBeVisible({ timeout: 5000 });
    // Password field should be hidden (passwordlessEnabled = true)
    await expect(page.locator('#password')).toBeHidden();
    console.log('✓  Password form hidden; Security Key button shown in passwordless mode');
  });
});
