/**
 * MFA enforcement tests for wang@gmail.com
 * Verifies that when TOTP is enabled, "Password only" bypass is gone
 * and login always requires the second factor.
 */

import { test, expect } from '@playwright/test';
import { encode, decode } from '@msgpack/msgpack';

const BASE  = 'http://localhost:1234';
const EMAIL = 'wang@gmail.com';
const PASS  = 'name';

function mockDaemon(page: import('@playwright/test').Page, opts: {
  totp_enabled?: boolean;
  email_otp_enabled?: boolean;
  password_login_enabled?: boolean;
} = {}) {
  const {
    totp_enabled           = false,
    email_otp_enabled      = false,
    password_login_enabled = true,
  } = opts;

  return page.routeWebSocket(/\/ws$/, ws => {
    ws.onMessage((raw: Buffer | string) => {
      const body = Buffer.isBuffer(raw) ? raw : Buffer.from(raw as string);
      let req: { cmd: string };
      try { req = decode(body) as typeof req; } catch { return; }

      let resp: unknown;
      switch (req.cmd) {
        case 'Ping':
          resp = { status: 'Pong' }; break;
        case 'GetLoginHints':
          resp = {
            status: 'LoginHints',
            data: { password_login_enabled, totp_enabled, email_otp_enabled, fido2_ids: [] },
          }; break;
        case 'Unlock':
          resp = { status: 'Unlocked', data: { session_token: 'mock-token', wipe_ticket: [] } }; break;
        case 'GetProfile':
          resp = { status: 'Profile', data: { first_name: 'Wang', last_name: 'Test', email: EMAIL } }; break;
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

test.describe('MFA enforcement — wang@gmail.com', () => {

  test('no MFA configured: password form shown directly, no method cards', async ({ page }) => {
    await mockDaemon(page, { totp_enabled: false });
    await page.goto(`${BASE}/login`);

    await page.fill('#email', EMAIL);
    await page.click('button[type=submit]');
    await page.waitForTimeout(1500);

    // Should go straight to password field — no method-selection cards
    await expect(page.locator('#password')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('text=Password only')).not.toBeVisible();
    await expect(page.locator('text=Authenticator App')).not.toBeVisible();

    console.log('PASS: No MFA → direct password form, no bypass card');
  });

  test('TOTP enabled: Password only bypass card is NOT shown', async ({ page }) => {
    await mockDaemon(page, { totp_enabled: true });
    await page.goto(`${BASE}/login`);

    // Inject hints so the UI shows MFA cards
    await page.evaluate(() => {
      localStorage.setItem('_pwdn_login_hints', JSON.stringify({
        totp: true, emailOtp: false, passwordEnabled: true,
        webauthn: false, passwordlessEnabled: false,
      }));
    });

    await page.route('**/api/vault/mfa', route => {
      route.fulfill({
        status: 200,
        body: JSON.stringify({
          totp: { enabled: true, secret: 'JBSWY3DPEHPK3PXP', enabledAt: Date.now() },
          webauthn: { enabled: false, credentials: [] },
          passkey:  { enabled: false, credentials: [] },
          platform: { enabled: false, credentials: [] },
          email:    { enabled: false },
          passwordLoginEnabled: true,
        })
      });
    });

    await page.fill('#email', EMAIL);
    await page.click('button[type=submit]');
    await page.waitForTimeout(1500);

    // "Password + Authenticator App" card must be present
    await expect(page.locator('text=Password + Authenticator App')).toBeVisible({ timeout: 5000 });

    // "Password only" bypass card must NOT exist
    await expect(page.locator('text=Password only')).not.toBeVisible();
    console.log('PASS: TOTP enabled → no "Password only" bypass');
  });

  test('TOTP enabled: completing password always advances to TOTP step', async ({ page }) => {
    await mockDaemon(page, { totp_enabled: true });
    await page.goto(`${BASE}/login`);

    await page.evaluate(() => {
      localStorage.setItem('_pwdn_login_hints', JSON.stringify({
        totp: true, emailOtp: false, passwordEnabled: true,
        webauthn: false, passwordlessEnabled: false,
      }));
    });

    await page.route('**/api/vault/mfa', route => {
      route.fulfill({
        status: 200,
        body: JSON.stringify({
          totp: { enabled: true, secret: 'JBSWY3DPEHPK3PXP', enabledAt: Date.now() },
          webauthn: { enabled: false, credentials: [] },
          passkey:  { enabled: false, credentials: [] },
          platform: { enabled: false, credentials: [] },
          email:    { enabled: false },
          passwordLoginEnabled: true,
        })
      });
    });

    await page.fill('#email', EMAIL);
    await page.click('button[type=submit]');
    await page.waitForTimeout(1500);

    // Click the "Password + Authenticator App" card
    await page.locator('button', { hasText: 'Authenticator App' }).click();
    await page.waitForSelector('#password', { timeout: 5000 });

    // Enter password
    await page.fill('#password', PASS);
    await page.click('button[type=submit]');
    await page.waitForTimeout(2000);

    // Must be on TOTP step — 6-digit input boxes visible
    const totpInput = page.locator('input[inputmode="numeric"]').first();
    await expect(totpInput).toBeVisible({ timeout: 5000 });
    await expect(page.locator('text=Two-Step Verification')).toBeVisible();

    // Must NOT have navigated to vault
    expect(page.url()).not.toContain('/vault');

    console.log('PASS: Password alone does not complete login — TOTP step required');
  });

});
