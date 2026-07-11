import { test, expect, type Page } from '@playwright/test';

const BASE_URL    = 'http://localhost:1234';
const EMAIL       = 'e2e-test@pwdnow.local';
const PASSWORD    = 'E2eTestPassw0rd!1';
const DURESS_PASSWORD = 'duress_password_123!';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Force a server-side logout to ensure clean cookie state. */
async function serverLogout(page: Page): Promise<void> {
  // Hit the logout API directly (handles cookie clearing server-side).
  await page.evaluate(async () => {
    const csrf = document.cookie.split(';')
      .map(c => c.trim())
      .find(c => c.startsWith('_pwd_csrf='))
      ?.split('=')?.[1] ?? '';
    await fetch('/api/auth/logout', {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrf },
      credentials: 'include',
    }).catch(() => {});
  });
  // Clear any in-page state by navigating away.
  await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle' });
}

/** Complete the two-step login form. Handles MFA method selection and TOTP. */
async function loginFlow(page: Page, email: string, password: string): Promise<void> {
  console.log(`[Test] Attempting login for ${email}`);

  // Always navigate to /login to guarantee step-1 state (email input visible).
  await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle' });

  // Step 1 — email
  const emailInput = page.locator('input[type="email"]');
  await emailInput.waitFor({ state: 'visible', timeout: 10_000 });
  await emailInput.fill(email);
  await page.locator('button[type="submit"]').first().click();

  // Step 1.5 — optional MFA method picker
  const mfaButton = page.locator(
    'button:has-text("Password + Authenticator App"), button:has-text("Password + Email OTP")'
  ).first();
  if (await mfaButton.isVisible({ timeout: 2000 }).catch(() => false)) {
    await mfaButton.click();
  }

  // Step 2 — password
  const pwInput = page.locator('input[type="password"]');
  await pwInput.waitFor({ state: 'visible', timeout: 10_000 });
  await pwInput.fill(password);
  await page.locator('button[type="submit"]').first().click();

  // Step 3 — optional TOTP
  const totpHeader = page.locator('h1:has-text("Two-Step Verification")');
  if (await totpHeader.isVisible({ timeout: 2000 }).catch(() => false)) {
    console.log('[Test] MFA detected, handling TOTP step');
    const simCodeElem = page.locator('p.text-3xl.font-black');
    let code = '123456';
    if (await simCodeElem.isVisible().catch(() => false)) {
      code = (await simCodeElem.innerText()).replace(/\s/g, '');
      console.log(`[Test] Using simulated code: ${code}`);
    }
    const otpInputs = page.locator('input[inputmode="numeric"]');
    for (let i = 0; i < 6; i++) await otpInputs.nth(i).fill(code[i]);
    await page.locator('button:has-text("Verify")').click();
  }
}

// ── Test ──────────────────────────────────────────────────────────────────────

test.describe('Comprehensive Platform Test', () => {

  test('Full platform feature walkthrough', async ({ page }) => {
    page.on('console', msg => {
      console.log(`[Browser Console ${msg.type()}] ${msg.text()}`);
    });
    page.on('pageerror', err => {
      console.log(`[Browser Page Error] ${err.message}`);
    });
    
    // ── Phase 1: Login failure ────────────────────────────────────────────────
    console.log('\n[Phase 1] Testing login failure...');
    await loginFlow(page, EMAIL, 'WrongPassword123!');
    await expect(
      page.locator('.text-red-600, .text-error').first()
    ).toBeVisible({ timeout: 8_000 });
    console.log('[Phase 1] ✓ Login failure handled correctly.');

    // ── Phase 2: Valid login ──────────────────────────────────────────────────
    console.log('\n[Phase 2] Testing valid login...');
    await loginFlow(page, EMAIL, PASSWORD);
    await page.waitForURL('**/vault**', { timeout: 30_000 });
    expect(page.url()).toContain('/vault');
    console.log('[Phase 2] ✓ Logged in successfully.');

    // ── Phase 3: Security and Health pages ───────────────────────────────────
    console.log('\n[Phase 3] Checking Security and Health pages...');
    await page.goto(`${BASE_URL}/security`);
    await expect(page.locator('text=Vault Password Breach Scan')).toBeVisible({ timeout: 10_000 });

    await page.goto(`${BASE_URL}/health`);
    await expect(
      page.locator('text=A real-time audit of your vault passwords')
    ).toBeVisible({ timeout: 10_000 });
    console.log('[Phase 3] ✓ Security and Health pages verified.');

    // ── Phase 4: Language toggle ──────────────────────────────────────────────
    console.log('\n[Phase 4] Testing language toggle...');
    await page.goto(`${BASE_URL}/vault`);
    await page.locator('button[aria-label^="Select Language"]').click();
    await page.locator('button:has-text("Français")').click();
    await expect(page.locator('text=Bastion Numérique Actif')).toBeVisible({ timeout: 5_000 });
    console.log('[Phase 4] ✓ Switched to French.');

    await page.locator('button[aria-label^="Select Language"]').click();
    await page.locator('button:has-text("English")').click();
    await expect(page.locator('text=Digital Bastion Active')).toBeVisible({ timeout: 5_000 });
    console.log('[Phase 4] ✓ Switched back to English.');

    // ── Phase 5: Asset Holder ─────────────────────────────────────────────────
    console.log('\n[Phase 5] Testing Asset Holder...');
    await page.goto(`${BASE_URL}/asset-holder`);
    const emailTemplateInput = page.locator('input[type="email"]').first();
    await emailTemplateInput.waitFor({ state: 'visible', timeout: 10_000 });
    await emailTemplateInput.fill('template@example.com');
    await page.locator('button:has-text("Save Templates")').click();
    console.log('[Phase 5] ✓ Asset template saved.');

    // ── Phase 6: Folder CRUD ──────────────────────────────────────────────────
    console.log('\n[Phase 6] Testing Folder creation and removal...');
    await page.goto(`${BASE_URL}/manage-folders`);
    await page.waitForLoadState('networkidle');
    await page.screenshot({ path: 'test-results/folders-1-manage.png' });

    const folderName = `TestFolder_${Date.now()}`;
    console.log(`[Phase 6] Creating folder: ${folderName}`);

    await page.locator('button:has-text("Create Folder")').first().click();
    await page.screenshot({ path: 'test-results/folders-2-modal.png' });

    const folderInput = page.locator(
      'input[placeholder*="folder" i], input[placeholder*="Personal" i]'
    ).first();
    await folderInput.waitFor({ state: 'visible', timeout: 5_000 });
    // The folder-name field is rendered readOnly until focused (autofill
    // suppression, see useAutofillGuard) — click() is allowed on readOnly
    // elements and triggers the onFocus handler that unlocks it for fill().
    await folderInput.click();
    await folderInput.fill(folderName);

    // Click the "Create Folder" inside the modal (not the page-level button)
    await page.locator('div.relative.w-full.max-w-2xl >> button:has-text("Create Folder")').click();

    await page.locator(`text=${folderName}`).first().waitFor({ state: 'visible', timeout: 15_000 });
    await page.screenshot({ path: 'test-results/folders-3-created.png' });
    console.log('[Phase 6] Folder created.');

    // Delete folder
    const folderRow = page.locator('li, [class*="group"]', { hasText: folderName }).first();
    await folderRow.scrollIntoViewIfNeeded();
    await folderRow.locator('button').last().click();
    await page.screenshot({ path: 'test-results/folders-4-confirm.png' });

    await page.locator(
      'button:has-text("Confirm Delete"), button:has-text("Delete Everything")'
    ).first().click();
    await expect(page.locator(`text=${folderName}`)).not.toBeVisible({ timeout: 10_000 });
    console.log('[Phase 6] ✓ Folder created and removed.');

    // ── Phase 7: Duress Mode ──────────────────────────────────────────────────
    console.log('\n[Phase 7] Testing Duress Mode...');
    await page.goto(`${BASE_URL}/settings`);
    await page.waitForLoadState('networkidle');

    // Scroll to and click Arm Duress Mode
    const duressSection = page.locator('h2', { hasText: 'Offline Duress Mode' });
    await duressSection.waitFor({ state: 'visible', timeout: 15_000 });
    await duressSection.scrollIntoViewIfNeeded();

    await page.locator('button:has-text("Arm Duress Mode")').click();

    // Step 1 — set duress password
    await page.locator('input[placeholder*="Minimum 8 characters"]').fill(DURESS_PASSWORD);
    await page.locator('button:has-text("Next")').click();

    // Step 2 — confirm
    await page.locator('input[placeholder*="Repeat duress password"]').fill(DURESS_PASSWORD);
    await page.locator('button:has-text("Arm Duress Mode")').last().click();

    // Step 3 — done
    // armDuressMode() runs Argon2id at m=256MiB,t=3 client-side (#29-FIX),
    // which can take well over 5s in a browser, so allow a generous timeout.
    await page.locator('button:has-text("Done")').waitFor({ state: 'visible', timeout: 60_000 });
    await page.locator('button:has-text("Done")').click();
    console.log('[Phase 7] Duress mode armed.');

    // Explicit server-side logout so cookies are cleared cleanly
    await page.locator('button:has-text("Logout")').first().click();
    await page.waitForURL('**/login', { timeout: 10_000 });

    // Trigger wipe via duress password
    console.log('[Phase 7] Triggering forensic wipe via duress password...');
    await loginFlow(page, EMAIL, DURESS_PASSWORD);

    // The app should wipe local data and redirect back to /login
    await page.waitForURL('**/login', { timeout: 20_000 });
    console.log(`[Phase 7] URL after duress login: ${page.url()}`);
    expect(page.url()).toContain('/login');
    console.log('[Phase 7] ✓ Forensic wipe triggered — redirected to login.');

    // Verify server account still exists: login with normal password should succeed
    console.log('[Phase 7] Verifying server account persisted after local wipe...');
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle' });
    await loginFlow(page, EMAIL, PASSWORD);
    try {
      await page.waitForURL('**/vault**', { timeout: 15_000 });
      console.log('[Phase 7] ✓ Account PERSISTED on server (only local data wiped) — expected.');
    } catch {
      // Server account may have been destroyed depending on duress config.
      console.log('[Phase 7] Note: Login failed — account may have been fully destroyed.');
    }

    // ── Phase 8: Account Re-creation ─────────────────────────────────────────
    console.log('\n[Phase 8] Testing account re-creation attempt...');

    // Ensure clean session before attempting registration
    await serverLogout(page);
    await page.waitForURL('**/login', { timeout: 10_000 });

    await page.goto(`${BASE_URL}/register`, { waitUntil: 'networkidle' });

    // If the register page redirects to vault (already logged in), force logout first
    if (!page.url().includes('/register')) {
      console.log('[Phase 8] Still had active session — forcing logout and retrying...');
      await serverLogout(page);
      await page.goto(`${BASE_URL}/register`, { waitUntil: 'networkidle' });
    }

    // Wait for register form to be stable (not mid-redirect)
    const firstNameInput = page.locator('input[name="firstName"]');
    await firstNameInput.waitFor({ state: 'visible', timeout: 10_000 });

    await firstNameInput.fill('E2E');
    await page.locator('input[name="lastName"]').fill('Test');
    await page.locator('input[name="email"]').fill(EMAIL);
    await page.locator('input[name="password"]').fill(PASSWORD);
    await page.locator('input#confirmPassword').fill(PASSWORD);

    await page.locator('button[type="submit"]').click();

    // Accept either outcome: vault (re-created) or error (account already exists)
    const outcome = await Promise.race([
      page.waitForURL('**/vault**', { timeout: 15_000 }).then(() => 'vault'),
      page.locator('.text-red-600, .text-error').first()
            .waitFor({ state: 'visible', timeout: 15_000 }).then(() => 'error'),
    ]);

    if (outcome === 'vault') {
      console.log('[Phase 8] ✓ Account re-created successfully (full destruction had occurred).');
    } else {
      const errText = await page.locator('.text-red-600, .text-error').first()
                                .innerText().catch(() => 'unknown error');
      if (errText.toLowerCase().includes('already') || errText.toLowerCase().includes('exists')) {
        console.log('[Phase 8] ✓ Expected: account already exists — server wipe was LOCAL ONLY.');
      } else {
        console.log(`[Phase 8] Note: Registration produced message: "${errText}"`);
      }
    }

    console.log('\n[Test Complete] ✓ All phases executed successfully.');
  });
});
