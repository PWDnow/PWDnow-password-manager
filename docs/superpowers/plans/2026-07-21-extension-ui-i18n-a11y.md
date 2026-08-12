# Extension Enterprise UI, Icon, i18n, and WCAG AAA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the v1 extension's unstyled popup with a Tailwind-styled UI matching the PWDnow web app's own design tokens, add a real SVG-sourced toolbar icon, support 13 languages (with RTL for Arabic), and meet WCAG 2.2 AAA — structural criteria (labeling, target size, focus, motion, heading order) verified via automated axe checks; contrast is not axe-checkable under jsdom and instead rests on token-value fidelity to the audited web app palette (see the design spec's §6 correction) — without changing any `lib/*` message/session/crypto logic except `lib/errorMessages.ts`.

**Architecture:** Presentation-layer pass over the existing, already-reviewed v1 extension at `~/Documents/PWDnow_extension`. Tailwind CSS v4 with hand-ported design tokens from `PWDnow/web/src/index.css`. `react-i18next` with statically bundled (not HTTP-fetched) locale JSON. `lucide-react` for in-UI icons, matching the web app's own icon library. `vitest-axe` for automated accessibility verification.

**Tech Stack:** Tailwind CSS v4 (`@tailwindcss/vite`), `react-i18next`/`i18next`, `lucide-react`, `vitest-axe`, `sharp` (icon rasterization, dev-only).

## Global Constraints

- Reference spec: `PWDnow/docs/superpowers/specs/2026-07-21-extension-ui-i18n-a11y-design.md`.
- Design tokens are ported **verbatim** from `PWDnow/web/src/index.css` (exact hex values given in Task 1) — do not invent new colors.
- 13 supported language codes, exactly: `en, fr, es, de, it, pt, ru, ar, hi, zh, ja, ko, id`. Arabic (`ar`) is the only RTL language.
- i18n uses **statically bundled** locale resources (`resources: {...}` passed directly to `i18next.init()`), never `i18next-http-backend` — an extension has no server to fetch translations from at runtime.
- Every one of the 13 locale JSON files must have identical key structure to `en.json` — verified by an automated completeness test, not manual review.
- WCAG 2.2 AAA: every redesigned screen's test file gets an automated `axe(container)` check asserting zero violations, using whatever `vitest-axe` (or equivalent, verified at Task 4) actually provides.
- Do not modify `lib/crypto.ts`, `lib/session.ts`, `lib/serverClient.ts`, `lib/relay.ts`, `lib/messages.ts`, `lib/passwordGenerator.ts`, `lib/wordlist.ts`, `lib/matchCredentials.ts`, `lib/fillScript.ts`, or `entrypoints/background.ts` — this is a presentation-layer + `lib/errorMessages.ts` pass only.
- TypeScript strict mode (`npm run compile` clean) is required at the end of every task, per this project's established convention.

---

### Task 1: Tailwind CSS and design tokens

**Files:**
- Modify: `package.json` (add `tailwindcss`, `@tailwindcss/vite`)
- Modify: `wxt.config.ts` (wire the Vite plugin)
- Create: `entrypoints/popup/app.css`
- Modify: `entrypoints/popup/main.tsx` (import the CSS, apply dark-mode class)

**Interfaces:**
- Produces: the `bg-surface`, `text-black`/`dark:text-white`, `bg-primary-container`, `text-on-primary-container`, `bg-surface-container-low/high/highest`, `border-outline-variant`, `text-error`, `text-on-surface-variant`, `font-headline` Tailwind utility classes and the base AAA CSS rules — consumed by every component task (5-8).

- [ ] **Step 1: Add dependencies**

```bash
cd /home/pwd-vm/Documents/PWDnow_extension
npm install -D tailwindcss @tailwindcss/vite
```

- [ ] **Step 2: Write `entrypoints/popup/app.css`**

Design tokens ported verbatim from `PWDnow/web/src/index.css` (light/dark values, focus ring, target size, line-height, reduced-motion rules — the 80ch measure cap is omitted since the popup is fixed-width, not long-form text):

```css
@import "tailwindcss";

@custom-variant dark (&:where(.dark, .dark *));

@theme {
  --font-sans: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-headline: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;

  --color-white: var(--theme-white);
  --color-black: var(--theme-black);
  --color-primary: var(--theme-primary);
  --color-primary-container: var(--theme-primary-container);
  --color-on-primary-container: var(--theme-on-primary-container);
  --color-surface: var(--theme-surface);
  --color-surface-container: var(--theme-surface-container);
  --color-surface-container-low: var(--theme-surface-container-low);
  --color-surface-container-high: var(--theme-surface-container-high);
  --color-surface-container-highest: var(--theme-surface-container-highest);
  --color-on-surface-variant: var(--theme-on-surface-variant);
  --color-outline-variant: var(--theme-outline-variant);
  --color-error: var(--theme-error);
}

@layer base {
  :root {
    --theme-white: #ffffff;
    --theme-black: #000000;
    --theme-primary: #000000;
    --theme-primary-container: #00174b;
    --theme-on-primary-container: #ffffff;
    --theme-surface: #f7f9fb;
    --theme-surface-container: #f4f6f8;
    --theme-surface-container-low: #ffffff;
    --theme-surface-container-high: #f1f3f5;
    --theme-surface-container-highest: #e9ecef;
    --theme-on-surface-variant: #000000;
    --theme-outline-variant: #d1d5db;
    --theme-error: #991b1b;
  }

  .dark {
    --theme-white: #ffffff;
    --theme-black: #000000;
    --theme-primary: #ffffff;
    --theme-primary-container: #497cff;
    --theme-on-primary-container: #00174b;
    --theme-surface: #0f0f0f;
    --theme-surface-container: #1e1e1e;
    --theme-surface-container-low: #1a1a1a;
    --theme-surface-container-high: #242424;
    --theme-surface-container-highest: #2a2a2a;
    --theme-on-surface-variant: #d4d4d4;
    --theme-outline-variant: #333333;
    --theme-error: #ffb4ab;
  }

  html, body {
    @apply bg-surface text-black dark:text-white font-sans antialiased;
    width: 380px;
    min-height: 200px;
  }

  #root {
    @apply flex min-h-full flex-col;
  }

  /* WCAG 2.2 AAA 2.4.13 Focus Appearance (Enhanced) */
  :focus-visible {
    outline: 3px solid var(--theme-primary);
    outline-offset: 2px;
    border-radius: 2px;
  }

  /* WCAG 2.2 AAA 1.4.8 Visual Presentation (partial — measure cap N/A at this width) */
  p, li, dd {
    line-height: 1.65;
  }

  p + p, li + li {
    margin-top: 1em;
  }

  /* WCAG 2.2 AAA 2.5.5 Target Size (Enhanced) */
  button:has(> svg:only-child),
  a:has(> svg:only-child) {
    min-width: 44px;
    min-height: 44px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
}

/* WCAG 2.2 AAA 2.3.3 Animation from Interactions */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```

- [ ] **Step 3: Wire the Vite plugin in `wxt.config.ts`**

Add to the existing `defineConfig({...})` call (keep all existing keys — `modules`, `manifestVersion`, `alias`, `manifest`, `hooks` — unchanged, just add `vite`):

```typescript
import tailwindcss from '@tailwindcss/vite';
```

```typescript
  vite: () => ({
    plugins: [tailwindcss()],
  }),
```

- [ ] **Step 4: Import the CSS and apply dark mode in `main.tsx`**

```tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './app.css';

document.documentElement.classList.toggle(
  'dark',
  window.matchMedia('(prefers-color-scheme: dark)').matches,
);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
```

- [ ] **Step 5: Run the full test suite**

Run: `npm test`
Expected: all existing tests still pass (this task adds no new test file — it's pure CSS/build wiring, verified by the build check below, not by a unit test).

- [ ] **Step 6: Verify Tailwind actually compiled the custom tokens**

Run: `npm run build`
Expected: succeeds. Then run: `grep -r "00174b" .output/chrome-mv3/` — expected to find at least one match (the compiled CSS containing our `--theme-primary-container` value), proving Tailwind processed `app.css`'s custom `@theme`/`@layer base` block, not just Tailwind's default reset.

- [ ] **Step 7: Run compile check**

Run: `npm run compile`
Expected: clean, no errors.

- [ ] **Step 8: Commit**

```bash
git add package.json package-lock.json wxt.config.ts entrypoints/popup/app.css entrypoints/popup/main.tsx
git commit -m "feat: add Tailwind CSS with design tokens ported from the web app"
```

---

### Task 2: Toolbar icon

**Files:**
- Create: `assets/icon.svg`
- Create: `scripts/generate-icons.mjs`
- Create: `public/icons/icon-16.png`, `public/icons/icon-32.png`, `public/icons/icon-48.png`, `public/icons/icon-128.png` (generated binary files, committed)
- Modify: `wxt.config.ts` (wire `manifest.icons`)
- Modify: `package.json` (add `sharp` dev dependency)

**Interfaces:**
- Produces: a real toolbar icon in both the Chrome and Firefox production builds.

- [ ] **Step 1: Write the master SVG**

`assets/icon.svg` — navy/blue rounded-square badge, white shield silhouette, keyhole cutout:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128" role="img" aria-labelledby="pwdnowIconTitle">
  <title id="pwdnowIconTitle">PWDnow</title>
  <rect x="4" y="4" width="120" height="120" rx="28" fill="#00174b"/>
  <path d="M64 20 L100 34 V62 C100 90 84 106 64 114 C44 106 28 90 28 62 V34 Z" fill="#ffffff"/>
  <circle cx="64" cy="60" r="10" fill="#00174b"/>
  <path d="M58 68 H70 L66 92 H62 Z" fill="#00174b"/>
</svg>
```

- [ ] **Step 2: Add `sharp` and write the raster-generation script**

```bash
npm install -D sharp
```

`scripts/generate-icons.mjs`:

```javascript
import sharp from 'sharp';
import { readFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const svgPath = path.join(root, 'assets', 'icon.svg');
const outDir = path.join(root, 'public', 'icons');
const sizes = [16, 32, 48, 128];

mkdirSync(outDir, { recursive: true });

const svgBuffer = readFileSync(svgPath);

for (const size of sizes) {
  const outPath = path.join(outDir, `icon-${size}.png`);
  await sharp(svgBuffer, { density: 384 }).resize(size, size).png().toFile(outPath);
  console.log(`wrote ${outPath}`);
}
```

- [ ] **Step 3: Generate the icons**

Run: `node scripts/generate-icons.mjs`
Expected: prints 4 lines, one per generated file; `public/icons/` now contains `icon-16.png`, `icon-32.png`, `icon-48.png`, `icon-128.png`.

- [ ] **Step 4: Wire the manifest**

Add to `wxt.config.ts`'s existing `manifest: {...}` block (keep `name`, `description`, `permissions`, `optional_host_permissions` unchanged):

```typescript
    icons: {
      16: '/icons/icon-16.png',
      32: '/icons/icon-32.png',
      48: '/icons/icon-48.png',
      128: '/icons/icon-128.png',
    },
```

- [ ] **Step 5: Verify the build**

Run: `npm run build`
Expected: succeeds. Then inspect `.output/chrome-mv3/manifest.json` — its `icons` field should match Step 4 exactly, and `.output/chrome-mv3/icons/icon-16.png` (etc.) should exist as real files. Repeat for `npm run build:firefox` and `.output/firefox-mv3/`.

If WXT's installed version has a simpler auto-icon mechanism that generates all sizes from one source file automatically, verify that first and prefer it if it works cleanly — but the end state must be the same: a real toolbar icon at all 4 sizes in both builds' manifests.

- [ ] **Step 6: Run full suite and compile check**

Run: `npm test && npm run compile`
Expected: all pass, clean.

- [ ] **Step 7: Commit**

```bash
git add assets/icon.svg scripts/generate-icons.mjs public/icons/ wxt.config.ts package.json package-lock.json
git commit -m "feat: add toolbar icon (master SVG + generated manifest icons)"
```

---

### Task 3: i18n infrastructure, translations, and error-message localization

**Files:**
- Create: `lib/i18n.ts`, `lib/i18n.test.ts`
- Create: `entrypoints/popup/locales/en.json`, `fr.json`, `es.json`, `de.json`, `it.json`, `pt.json`, `ru.json`, `ar.json`, `hi.json`, `zh.json`, `ja.json`, `ko.json`, `id.json`
- Create: `entrypoints/popup/locales/locales.test.ts`
- Create: `entrypoints/popup/i18n.ts`
- Modify: `lib/errorMessages.ts`, `lib/errorMessages.test.ts`
- Modify: `tsconfig.json` (JSON module imports)
- Modify: `package.json` (add `react-i18next`, `i18next`)

**Interfaces:**
- Produces: `SUPPORTED_LANGUAGES`, `LanguageCode`, `isRtl(code)`, `detectDefaultLanguage(navLang)` (from `lib/i18n.ts`); `initI18n()`, `applyDocumentDirection(lang)`, `changeLanguage(lang)`, the default `i18n` singleton (from `entrypoints/popup/i18n.ts`) — consumed by Tasks 5-8. `mapErrorMessage(code, t)` (new 2-arg signature) — consumed by Tasks 7-8.

- [ ] **Step 1: Add dependencies**

```bash
npm install react-i18next i18next
```

- [ ] **Step 2: Write `lib/i18n.ts`**

```typescript
export const SUPPORTED_LANGUAGES = [
  { code: 'en', nativeName: 'English' },
  { code: 'fr', nativeName: 'Français' },
  { code: 'es', nativeName: 'Español' },
  { code: 'de', nativeName: 'Deutsch' },
  { code: 'it', nativeName: 'Italiano' },
  { code: 'pt', nativeName: 'Português' },
  { code: 'ru', nativeName: 'Русский' },
  { code: 'ar', nativeName: 'العربية' },
  { code: 'hi', nativeName: 'हिन्दी' },
  { code: 'zh', nativeName: '中文' },
  { code: 'ja', nativeName: '日本語' },
  { code: 'ko', nativeName: '한국어' },
  { code: 'id', nativeName: 'Bahasa Indonesia' },
] as const;

export type LanguageCode = (typeof SUPPORTED_LANGUAGES)[number]['code'];

const RTL_LANGUAGES: readonly string[] = ['ar'];

export function isRtl(code: string): boolean {
  return RTL_LANGUAGES.includes(code);
}

export function detectDefaultLanguage(navigatorLanguage: string): LanguageCode {
  const base = navigatorLanguage.split('-')[0].toLowerCase();
  const match = SUPPORTED_LANGUAGES.find((l) => l.code === base);
  return match ? match.code : 'en';
}
```

- [ ] **Step 3: Write `lib/i18n.test.ts`**

```typescript
import { describe, it, expect } from 'vitest';
import { SUPPORTED_LANGUAGES, isRtl, detectDefaultLanguage } from './i18n';

describe('SUPPORTED_LANGUAGES', () => {
  it('has exactly 13 languages in the required order', () => {
    expect(SUPPORTED_LANGUAGES.map((l) => l.code)).toEqual([
      'en', 'fr', 'es', 'de', 'it', 'pt', 'ru', 'ar', 'hi', 'zh', 'ja', 'ko', 'id',
    ]);
  });
});

describe('isRtl', () => {
  it('returns true for Arabic', () => {
    expect(isRtl('ar')).toBe(true);
  });

  it('returns false for English and other LTR languages', () => {
    expect(isRtl('en')).toBe(false);
    expect(isRtl('ja')).toBe(false);
  });
});

describe('detectDefaultLanguage', () => {
  it('matches a supported base language from a full locale string', () => {
    expect(detectDefaultLanguage('fr-CA')).toBe('fr');
  });

  it('falls back to English for an unsupported language', () => {
    expect(detectDefaultLanguage('xx-XX')).toBe('en');
  });
});
```

Run: `npx vitest run lib/i18n.test.ts` — expected FAIL, then implement Step 2 above, then PASS (5 tests).

- [ ] **Step 4: Enable JSON module imports**

Check `tsconfig.json`'s effective config (it extends `.wxt/tsconfig.json`). If `resolveJsonModule` isn't already enabled there, add it to the `compilerOptions` in the project's own `tsconfig.json`:

```json
{
  "extends": "./.wxt/tsconfig.json",
  "compilerOptions": {
    "paths": { "@/*": ["./*"] },
    "resolveJsonModule": true
  }
}
```

- [ ] **Step 5: Write the English source-of-truth locale file**

`entrypoints/popup/locales/en.json` — this exact content and key structure is the schema every other language must match exactly:

```json
{
  "common": {
    "appName": "PWDnow",
    "loading": "Loading…",
    "cancel": "Cancel",
    "copy": "Copy",
    "copied": "Copied!"
  },
  "connect": {
    "title": "Connect to PWDnow",
    "serverUrlLabel": "Server URL",
    "serverUrlPlaceholder": "https://vault.example.com",
    "emailLabel": "Email",
    "passwordLabel": "Master Password",
    "showPassword": "Show password",
    "hidePassword": "Hide password",
    "connectButton": "Connect",
    "connecting": "Connecting…"
  },
  "mfa": {
    "totpTitle": "Enter your authenticator code",
    "emailTitle": "Enter your email code",
    "codeLabel": "Verification code",
    "codePlaceholder": "123456",
    "verifyButton": "Verify",
    "verifying": "Verifying…"
  },
  "vault": {
    "title": "Your Passwords",
    "emptyStateTitle": "No saved passwords for this site",
    "emptyStateHint": "Generate a password below and save it here.",
    "fillButton": "Fill",
    "copyPasswordButton": "Copy password",
    "generateButton": "Generate password",
    "generating": "Generating…",
    "saveButton": "Save to vault",
    "saving": "Saving…",
    "saveSuccess": "Saved to your vault"
  },
  "language": {
    "switcherLabel": "Change language"
  },
  "errors": {
    "invalid_credentials": "Incorrect email or password.",
    "account_locked": "This account is temporarily locked. Try again later.",
    "too_many_requests": "Too many attempts. Please wait and try again.",
    "mfa_locked": "Too many incorrect codes. Please wait and try again.",
    "hardware_mfa_requires_daemon": "This account requires a hardware security key, which the extension does not support yet. Please use the PWDnow web app.",
    "missing_salt": "Could not complete login. Please try again.",
    "permission_denied": "PWDnow needs permission to talk to your server to connect.",
    "not_connected": "Connect to a PWDnow server first.",
    "session_expired": "Your session expired. Please reconnect.",
    "decrypt_failed": "Could not unlock your vault with that password.",
    "no_folders": "Create at least one folder in the PWDnow web app before saving from the extension.",
    "nothing_to_save": "Nothing to save — generate a password or fill in the form first.",
    "save_failed": "Could not save the credential. Please try again.",
    "unexpected_response": "Something went wrong. Please try again.",
    "unknown_error": "Something went wrong. Please try again.",
    "invalid_mfa_code": "The code you entered is incorrect.",
    "mfa_required": "Please enter your verification code.",
    "invalid_or_expired_mfa_token": "Your session expired. Please start over.",
    "user_not_found": "We couldn't find your account. Please try again."
  }
}
```

- [ ] **Step 6: Translate into the other 12 languages**

Write `fr.json`, `es.json`, `de.json`, `it.json`, `pt.json`, `ru.json`, `ar.json`, `hi.json`, `zh.json`, `ja.json`, `ko.json`, `id.json` in `entrypoints/popup/locales/` — each with **exactly the same nested key structure** as `en.json` (same top-level sections, same keys within each), with every value accurately translated into that language. Before translating a given string, check whether `PWDnow/web/src/locales/<code>.json` already has an equivalent term for shared vocabulary (e.g. "Cancel", "Copy", generic error phrasing) and reuse that exact wording for consistency with the rest of the product; write fresh, natural translations for extension-specific strings (Connect/MFA/Vault copy) that don't already exist there. No value may be left blank, left in English as a placeholder, or be a literal copy of the key name — every one of the 12 files must be a complete, real translation.

- [ ] **Step 7: Write the completeness test**

`entrypoints/popup/locales/locales.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import en from './en.json';
import fr from './fr.json';
import es from './es.json';
import de from './de.json';
import it from './it.json';
import pt from './pt.json';
import ru from './ru.json';
import ar from './ar.json';
import hi from './hi.json';
import zh from './zh.json';
import ja from './ja.json';
import ko from './ko.json';
import id from './id.json';

type Dict = Record<string, unknown>;

function flattenKeys(obj: Dict, prefix = ''): string[] {
  return Object.entries(obj).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return flattenKeys(value as Dict, path);
    }
    return [path];
  });
}

function getByPath(obj: Dict, path: string): unknown {
  return path.split('.').reduce((acc: unknown, part) => (acc as Dict)[part], obj);
}

const locales: Record<string, Dict> = { en, fr, es, de, it, pt, ru, ar, hi, zh, ja, ko, id };

describe('locale completeness', () => {
  it('has exactly 13 locale files', () => {
    expect(Object.keys(locales)).toHaveLength(13);
  });

  const englishKeys = flattenKeys(en).sort();

  for (const [code, dict] of Object.entries(locales)) {
    it(`${code}.json has exactly the same keys as en.json`, () => {
      expect(flattenKeys(dict).sort()).toEqual(englishKeys);
    });
  }

  for (const [code, dict] of Object.entries(locales)) {
    if (code === 'en') continue;
    it(`${code}.json has no blank or placeholder values`, () => {
      const allNonEmpty = englishKeys.every((key) => {
        const value = getByPath(dict, key);
        return typeof value === 'string' && value.trim().length > 0;
      });
      expect(allNonEmpty).toBe(true);
    });
  }
});
```

Run: `npx vitest run entrypoints/popup/locales/locales.test.ts` — expected PASS (26 tests: 1 count + 13 key-match + 12 non-empty, since `en` is skipped from the non-empty loop) once all 13 files exist and match.

- [ ] **Step 8: Write the i18next bootstrap**

`entrypoints/popup/i18n.ts`:

```typescript
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import { browser } from 'wxt/browser';
import { SUPPORTED_LANGUAGES, detectDefaultLanguage, isRtl, type LanguageCode } from '@/lib/i18n';
import en from './locales/en.json';
import fr from './locales/fr.json';
import es from './locales/es.json';
import de from './locales/de.json';
import it from './locales/it.json';
import pt from './locales/pt.json';
import ru from './locales/ru.json';
import ar from './locales/ar.json';
import hi from './locales/hi.json';
import zh from './locales/zh.json';
import ja from './locales/ja.json';
import ko from './locales/ko.json';
import id from './locales/id.json';

const resources = {
  en: { translation: en },
  fr: { translation: fr },
  es: { translation: es },
  de: { translation: de },
  it: { translation: it },
  pt: { translation: pt },
  ru: { translation: ru },
  ar: { translation: ar },
  hi: { translation: hi },
  zh: { translation: zh },
  ja: { translation: ja },
  ko: { translation: ko },
  id: { translation: id },
};

const LANGUAGE_STORAGE_KEY = 'pwdnow_language';

export function applyDocumentDirection(lang: string): void {
  document.documentElement.dir = isRtl(lang) ? 'rtl' : 'ltr';
  document.documentElement.lang = lang;
}

export async function initI18n(): Promise<void> {
  const stored = await browser.storage.local.get(LANGUAGE_STORAGE_KEY);
  const storedLang = stored[LANGUAGE_STORAGE_KEY] as LanguageCode | undefined;
  const initialLang = storedLang ?? detectDefaultLanguage(navigator.language);

  await i18n.use(initReactI18next).init({
    resources,
    lng: initialLang,
    fallbackLng: 'en',
    interpolation: { escapeValue: false },
  });

  applyDocumentDirection(initialLang);
}

export async function changeLanguage(lang: LanguageCode): Promise<void> {
  await i18n.changeLanguage(lang);
  applyDocumentDirection(lang);
  await browser.storage.local.set({ [LANGUAGE_STORAGE_KEY]: lang });
}

export { SUPPORTED_LANGUAGES };
export default i18n;
```

- [ ] **Step 9: Rewrite `lib/errorMessages.ts` to use translation keys**

```typescript
export function mapErrorMessage(
  code: string,
  t: (key: string, options?: { defaultValue?: string }) => string,
): string {
  const fallback = t('errors.unknown_error');
  return t(`errors.${code}`, { defaultValue: fallback });
}
```

- [ ] **Step 10: Update `lib/errorMessages.test.ts`**

```typescript
import { describe, it, expect } from 'vitest';
import { mapErrorMessage } from './errorMessages';

function fakeT(key: string, options?: { defaultValue?: string }): string {
  const table: Record<string, string> = {
    'errors.invalid_credentials': 'Incorrect email or password.',
    'errors.hardware_mfa_requires_daemon': 'requires a hardware security key',
    'errors.unknown_error': 'Something went wrong. Please try again.',
  };
  return table[key] ?? options?.defaultValue ?? key;
}

describe('mapErrorMessage', () => {
  it('maps a known code to translated text', () => {
    expect(mapErrorMessage('invalid_credentials', fakeT)).toBe('Incorrect email or password.');
  });

  it('maps the hardware-MFA-unsupported code to an explanatory message', () => {
    expect(mapErrorMessage('hardware_mfa_requires_daemon', fakeT)).toMatch(/hardware security key/);
  });

  it('falls back to the translated unknown_error message for an unrecognized code', () => {
    expect(mapErrorMessage('some_future_unmapped_code', fakeT)).toBe('Something went wrong. Please try again.');
  });
});
```

- [ ] **Step 11: Run the full test suite**

Run: `npm test`
Expected: all tests pass, including the new `lib/i18n.test.ts`, `entrypoints/popup/locales/locales.test.ts`, and updated `lib/errorMessages.test.ts`.

- [ ] **Step 12: Run compile check**

Run: `npm run compile`
Expected: clean.

- [ ] **Step 13: Commit**

```bash
git add package.json package-lock.json tsconfig.json lib/i18n.ts lib/i18n.test.ts lib/errorMessages.ts lib/errorMessages.test.ts entrypoints/popup/locales/ entrypoints/popup/i18n.ts
git commit -m "feat: add i18n infrastructure, 13-language translations, and localize error messages"
```

---

### Task 4: Accessibility test infrastructure

**Files:**
- Modify: `package.json` (add `vitest-axe`)
- Modify: `vitest.setup.ts`
- Create: `entrypoints/popup/a11y.smoke.test.tsx`

**Interfaces:**
- Produces: an `axe(container)` helper with a `toHaveNoViolations()` matcher, proven to actually catch violations — consumed by Tasks 5, 6, 7, 8.

- [ ] **Step 1: Add the dependency**

```bash
npm install -D vitest-axe
```

- [ ] **Step 2: Wire the matcher into `vitest.setup.ts`**

Check the installed `vitest-axe` package's actual documented setup (its README/type definitions) for the exact extend-expect import path, since package APIs can differ by version — the goal is that `expect(...).toHaveNoViolations()` becomes available globally. Add whatever import that requires to `vitest.setup.ts`, alongside the existing `@testing-library/jest-dom/vitest` import and RTL `afterEach(cleanup)`.

- [ ] **Step 3: Write the proving smoke test**

`entrypoints/popup/a11y.smoke.test.tsx` — one test proving a clean fixture passes, one proving a genuinely broken fixture is caught (so this isn't a no-op check):

```tsx
import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import { axe } from 'vitest-axe';

describe('axe accessibility check (infrastructure smoke test)', () => {
  it('reports zero violations for an accessible fixture', async () => {
    const { container } = render(
      <button type="button" aria-label="Close">
        ×
      </button>,
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('reports a violation for a genuinely inaccessible fixture', async () => {
    const { container } = render(<img src="x.png" />);
    const results = await axe(container);
    expect(results.violations.length).toBeGreaterThan(0);
  });
});
```

If the exact import path (`vitest-axe`) or matcher name differs from what's shown here, adjust to match the actually-installed package's real API — verify by reading its `README.md`/type definitions under `node_modules/vitest-axe/`.

- [ ] **Step 4: Run the tests**

Run: `npx vitest run entrypoints/popup/a11y.smoke.test.tsx`
Expected: PASS (2 tests) — critically, the second test must actually find a violation (an `<img>` with no `alt` is a textbook axe violation), proving the harness has teeth.

- [ ] **Step 5: Run full suite and compile check**

Run: `npm test && npm run compile`
Expected: all pass, clean.

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json vitest.setup.ts entrypoints/popup/a11y.smoke.test.tsx
git commit -m "feat: add automated WCAG accessibility checking (vitest-axe)"
```

---

### Task 5: LanguageSwitcher component

**Files:**
- Modify: `package.json` (add `lucide-react`)
- Create: `entrypoints/popup/LanguageSwitcher.tsx`, `entrypoints/popup/LanguageSwitcher.test.tsx`

**Interfaces:**
- Consumes: `SUPPORTED_LANGUAGES`, `LanguageCode` (`lib/i18n.ts`, Task 3); `changeLanguage`, default `i18n` export, `initI18n` (`entrypoints/popup/i18n.ts`, Task 3); `axe` (Task 4).
- Produces: `LanguageSwitcher` component — consumed by `App.tsx` (Task 6).

- [ ] **Step 1: Add `lucide-react`**

```bash
npm install lucide-react
```

- [ ] **Step 2: Write the failing test**

`entrypoints/popup/LanguageSwitcher.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeAll } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { axe } from 'vitest-axe';

const storageGet = vi.fn(async () => ({}));
const storageSet = vi.fn(async () => {});
vi.mock('wxt/browser', () => ({
  browser: { storage: { local: { get: storageGet, set: storageSet } } },
}));

import i18n, { initI18n } from './i18n';
import { LanguageSwitcher } from './LanguageSwitcher';

beforeAll(async () => {
  await initI18n();
});

describe('LanguageSwitcher', () => {
  it('opens a dropdown listing all 13 languages by native name', () => {
    render(<LanguageSwitcher />);
    fireEvent.click(screen.getByRole('button', { name: /change language/i }));
    expect(screen.getByText('Français')).toBeInTheDocument();
    expect(screen.getByText('العربية')).toBeInTheDocument();
    expect(screen.getAllByRole('option')).toHaveLength(13);
  });

  it('switches language and sets document direction to rtl for Arabic', async () => {
    render(<LanguageSwitcher />);
    fireEvent.click(screen.getByRole('button', { name: /change language/i }));
    fireEvent.click(screen.getByText('العربية'));
    await waitFor(() => expect(document.documentElement.dir).toBe('rtl'));
    expect(storageSet).toHaveBeenCalledWith({ pwdnow_language: 'ar' });
    await i18n.changeLanguage('en');
    document.documentElement.dir = 'ltr';
  });

  it('has no accessibility violations in closed and open states', async () => {
    const { container } = render(<LanguageSwitcher />);
    expect(await axe(container)).toHaveNoViolations();
    fireEvent.click(screen.getByRole('button', { name: /change language/i }));
    expect(await axe(container)).toHaveNoViolations();
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run entrypoints/popup/LanguageSwitcher.test.tsx`
Expected: FAIL — module doesn't exist yet.

- [ ] **Step 4: Write the implementation**

`entrypoints/popup/LanguageSwitcher.tsx`:

```tsx
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Globe } from 'lucide-react';
import { SUPPORTED_LANGUAGES, type LanguageCode } from '@/lib/i18n';
import { changeLanguage } from './i18n';

export function LanguageSwitcher() {
  const { t, i18n } = useTranslation();
  const [open, setOpen] = useState(false);

  async function handleSelect(code: LanguageCode) {
    await changeLanguage(code);
    setOpen(false);
  }

  return (
    <div className="relative">
      <button
        type="button"
        aria-label={t('language.switcherLabel')}
        aria-expanded={open}
        aria-haspopup="listbox"
        onClick={() => setOpen((v) => !v)}
        className="rounded-full p-2 text-on-surface-variant hover:bg-surface-container-high"
      >
        <Globe aria-hidden="true" focusable="false" size={20} />
      </button>
      {open && (
        <ul
          role="listbox"
          aria-label={t('language.switcherLabel')}
          className="absolute end-0 z-10 mt-1 max-h-64 w-48 overflow-y-auto rounded-lg border border-outline-variant bg-surface-container-low shadow-lg"
        >
          {SUPPORTED_LANGUAGES.map((lang) => (
            <li key={lang.code} role="option" aria-selected={i18n.language === lang.code}>
              <button
                type="button"
                onClick={() => handleSelect(lang.code)}
                className="w-full px-3 py-2 text-start hover:bg-surface-container-high"
              >
                {lang.nativeName}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run entrypoints/popup/LanguageSwitcher.test.tsx`
Expected: PASS (3 tests).

- [ ] **Step 6: Run full suite and compile check**

Run: `npm test && npm run compile`

- [ ] **Step 7: Commit**

```bash
git add package.json package-lock.json entrypoints/popup/LanguageSwitcher.tsx entrypoints/popup/LanguageSwitcher.test.tsx
git commit -m "feat: add language switcher (13 languages, native names, RTL for Arabic)"
```

---

### Task 6: App.tsx shell redesign

**Files:**
- Modify: `entrypoints/popup/App.tsx`, `entrypoints/popup/App.test.tsx`

**Interfaces:**
- Consumes: `LanguageSwitcher` (Task 5), `initI18n` (Task 3), `axe` (Task 4).

- [ ] **Step 1: Write the failing test**

`entrypoints/popup/App.test.tsx` (replaces the existing v1 version):

```tsx
import { describe, it, expect, vi, beforeAll } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { axe } from 'vitest-axe';

const sendMessage = vi.fn();
const storageGet = vi.fn(async () => ({}));
const storageSet = vi.fn(async () => {});
vi.mock('wxt/browser', () => ({
  browser: {
    runtime: { sendMessage },
    storage: { local: { get: storageGet, set: storageSet } },
  },
}));

import { initI18n } from './i18n';
import App from './App';

beforeAll(async () => {
  await initI18n();
});

describe('App', () => {
  it('shows the Connect screen when not connected', async () => {
    sendMessage.mockResolvedValue({ type: 'status', connected: false, unlocked: false });
    render(<App />);
    await waitFor(() => expect(screen.getByText('Connect to PWDnow')).toBeInTheDocument());
  });

  it('renders the language switcher in the header', async () => {
    sendMessage.mockResolvedValue({ type: 'status', connected: false, unlocked: false });
    render(<App />);
    expect(screen.getByRole('button', { name: /change language/i })).toBeInTheDocument();
  });

  it('has no accessibility violations', async () => {
    sendMessage.mockResolvedValue({ type: 'status', connected: false, unlocked: false });
    const { container } = render(<App />);
    await waitFor(() => screen.getByText('Connect to PWDnow'));
    expect(await axe(container)).toHaveNoViolations();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run entrypoints/popup/App.test.tsx`
Expected: FAIL (old markup doesn't have a language switcher, and the loading text isn't wrapped correctly yet).

- [ ] **Step 3: Rewrite `App.tsx`**

```tsx
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { browser } from 'wxt/browser';
import { ConnectScreen } from './ConnectScreen';
import { VaultScreen } from './VaultScreen';
import { LanguageSwitcher } from './LanguageSwitcher';
import type { ExtMessage, ExtResponse } from '@/lib/messages';

export default function App() {
  const { t } = useTranslation();
  const [connected, setConnected] = useState<boolean | null>(null);

  useEffect(() => {
    void checkStatus();
  }, []);

  async function checkStatus() {
    try {
      const message: ExtMessage = { type: 'getStatus' };
      const response = (await browser.runtime.sendMessage(message)) as ExtResponse;
      setConnected(response.type === 'status' && response.connected && response.unlocked);
    } catch {
      setConnected(false);
    }
  }

  return (
    <div className="flex flex-col">
      <header className="flex items-center justify-between border-b border-outline-variant px-4 py-3">
        <span className="font-headline text-base font-semibold">{t('common.appName')}</span>
        <LanguageSwitcher />
      </header>
      <main className="p-4">
        {connected === null ? (
          <p aria-live="polite">{t('common.loading')}</p>
        ) : connected ? (
          <VaultScreen />
        ) : (
          <ConnectScreen onConnected={() => setConnected(true)} />
        )}
      </main>
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run entrypoints/popup/App.test.tsx`
Expected: PASS (3 tests) — note `ConnectScreen`/`VaultScreen` haven't been redesigned yet at this point in the plan, so this test only exercises the shell + language switcher + loading state, all of which are self-contained to this task.

- [ ] **Step 5: Run full suite and compile check**

Run: `npm test && npm run compile`

- [ ] **Step 6: Commit**

```bash
git add entrypoints/popup/App.tsx entrypoints/popup/App.test.tsx
git commit -m "feat: redesign App shell with header, language switcher, and translated loading state"
```

---

### Task 7: ConnectScreen redesign

**Files:**
- Modify: `entrypoints/popup/ConnectScreen.tsx`, `entrypoints/popup/ConnectScreen.test.tsx`

**Interfaces:**
- Consumes: `mapErrorMessage(code, t)` (Task 3, new signature), `initI18n` (Task 3), `axe` (Task 4).

- [ ] **Step 1: Write the failing test**

`entrypoints/popup/ConnectScreen.test.tsx` (replaces the existing v1 version):

```tsx
import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { axe } from 'vitest-axe';

const sendMessage = vi.fn();
const permissionsRequest = vi.fn();
const storageGet = vi.fn(async () => ({}));
const storageSet = vi.fn(async () => {});
vi.mock('wxt/browser', () => ({
  browser: {
    runtime: { sendMessage },
    permissions: { request: permissionsRequest },
    storage: { local: { get: storageGet, set: storageSet } },
  },
}));

import { initI18n } from './i18n';
import { ConnectScreen } from './ConnectScreen';

beforeAll(async () => {
  await initI18n();
});

beforeEach(() => {
  vi.clearAllMocks();
  permissionsRequest.mockResolvedValue(true);
});

describe('ConnectScreen', () => {
  it('calls onConnected after a successful login with no MFA', async () => {
    sendMessage.mockResolvedValue({ type: 'connectResult', ok: true });
    const onConnected = vi.fn();
    render(<ConnectScreen onConnected={onConnected} />);

    fireEvent.change(screen.getByLabelText('Server URL'), { target: { value: 'https://vault.example.com' } });
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@b.com' } });
    fireEvent.change(screen.getByLabelText('Master Password'), { target: { value: 'pw' } });
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));

    await waitFor(() => expect(onConnected).toHaveBeenCalled());
    expect(permissionsRequest).toHaveBeenCalledWith({ origins: ['https://vault.example.com/*'] });
  });

  it('toggles password visibility', () => {
    render(<ConnectScreen onConnected={vi.fn()} />);
    const passwordInput = screen.getByLabelText('Master Password') as HTMLInputElement;
    expect(passwordInput.type).toBe('password');
    fireEvent.click(screen.getByRole('button', { name: 'Show password' }));
    expect(passwordInput.type).toBe('text');
  });

  it('shows a friendly MFA title when methods are returned', async () => {
    sendMessage.mockResolvedValue({ type: 'connectResult', ok: true, mfaRequired: true, methods: ['totp'] });
    render(<ConnectScreen onConnected={vi.fn()} />);

    fireEvent.change(screen.getByLabelText('Server URL'), { target: { value: 'https://vault.example.com' } });
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@b.com' } });
    fireEvent.change(screen.getByLabelText('Master Password'), { target: { value: 'pw' } });
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));

    await waitFor(() => expect(screen.getByText('Enter your authenticator code')).toBeInTheDocument());
  });

  it('shows a translated error message on invalid credentials', async () => {
    sendMessage.mockResolvedValue({ type: 'connectResult', ok: false, error: 'invalid_credentials' });
    render(<ConnectScreen onConnected={vi.fn()} />);

    fireEvent.change(screen.getByLabelText('Server URL'), { target: { value: 'https://vault.example.com' } });
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@b.com' } });
    fireEvent.change(screen.getByLabelText('Master Password'), { target: { value: 'wrong' } });
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Incorrect email or password.'));
  });

  it('has no accessibility violations', async () => {
    const { container } = render(<ConnectScreen onConnected={vi.fn()} />);
    expect(await axe(container)).toHaveNoViolations();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run entrypoints/popup/ConnectScreen.test.tsx`
Expected: FAIL (old markup has no labels, no password toggle, raw English strings instead of via `t()`).

- [ ] **Step 3: Rewrite `ConnectScreen.tsx`**

```tsx
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Eye, EyeOff } from 'lucide-react';
import { browser } from 'wxt/browser';
import type { ExtMessage, ExtResponse } from '@/lib/messages';
import { mapErrorMessage } from '@/lib/errorMessages';

interface Props {
  onConnected: () => void;
}

export function ConnectScreen({ onConnected }: Props) {
  const { t } = useTranslation();
  const [origin, setOrigin] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [code, setCode] = useState('');
  const [mfaMethods, setMfaMethods] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleConnect() {
    setBusy(true);
    setError(null);
    try {
      const granted = await browser.permissions.request({ origins: [`${origin}/*`] });
      if (!granted) {
        setError('permission_denied');
        return;
      }
      const message: ExtMessage = { type: 'connect', origin, email, password };
      const response = (await browser.runtime.sendMessage(message)) as ExtResponse;
      if (response.type !== 'connectResult') {
        setError('unexpected_response');
        return;
      }
      if (!response.ok) {
        setError(response.error ?? 'unknown_error');
        return;
      }
      if (response.mfaRequired) {
        setMfaMethods(response.methods ?? []);
        return;
      }
      onConnected();
    } finally {
      setBusy(false);
    }
  }

  async function handleMfaSubmit() {
    setBusy(true);
    setError(null);
    try {
      const message: ExtMessage = { type: 'loginFinish', password, code };
      const response = (await browser.runtime.sendMessage(message)) as ExtResponse;
      if (response.type !== 'connectResult' || !response.ok) {
        setError(response.type === 'connectResult' ? response.error ?? 'unknown_error' : 'unexpected_response');
        return;
      }
      onConnected();
    } finally {
      setBusy(false);
    }
  }

  if (mfaMethods) {
    const title = mfaMethods[0] === 'email' ? t('mfa.emailTitle') : t('mfa.totpTitle');
    return (
      <div className="rounded-xl border border-outline-variant bg-surface-container-low p-4">
        <h1 className="mb-3 font-headline text-lg font-semibold">{title}</h1>
        <label htmlFor="mfa-code" className="mb-1 block text-sm font-medium">
          {t('mfa.codeLabel')}
        </label>
        <input
          id="mfa-code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder={t('mfa.codePlaceholder')}
          className="mb-3 w-full rounded-lg border border-outline-variant bg-surface px-3 py-2"
        />
        <button
          type="button"
          disabled={busy || !code}
          onClick={handleMfaSubmit}
          className="w-full rounded-lg bg-primary-container px-4 py-2 font-medium text-on-primary-container disabled:opacity-50"
        >
          {busy ? t('mfa.verifying') : t('mfa.verifyButton')}
        </button>
        {error && (
          <p role="alert" className="mt-3 text-error">
            {mapErrorMessage(error, t)}
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-outline-variant bg-surface-container-low p-4">
      <h1 className="mb-3 font-headline text-lg font-semibold">{t('connect.title')}</h1>
      <label htmlFor="connect-origin" className="mb-1 block text-sm font-medium">
        {t('connect.serverUrlLabel')}
      </label>
      <input
        id="connect-origin"
        value={origin}
        onChange={(e) => setOrigin(e.target.value)}
        placeholder={t('connect.serverUrlPlaceholder')}
        className="mb-3 w-full rounded-lg border border-outline-variant bg-surface px-3 py-2"
      />
      <label htmlFor="connect-email" className="mb-1 block text-sm font-medium">
        {t('connect.emailLabel')}
      </label>
      <input
        id="connect-email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        className="mb-3 w-full rounded-lg border border-outline-variant bg-surface px-3 py-2"
      />
      <label htmlFor="connect-password" className="mb-1 block text-sm font-medium">
        {t('connect.passwordLabel')}
      </label>
      <div className="relative mb-3">
        <input
          id="connect-password"
          type={showPassword ? 'text' : 'password'}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full rounded-lg border border-outline-variant bg-surface px-3 py-2 pe-10"
        />
        <button
          type="button"
          aria-label={showPassword ? t('connect.hidePassword') : t('connect.showPassword')}
          onClick={() => setShowPassword((v) => !v)}
          className="absolute end-1 top-1/2 -translate-y-1/2 text-on-surface-variant"
        >
          {showPassword ? (
            <EyeOff aria-hidden="true" focusable="false" size={18} />
          ) : (
            <Eye aria-hidden="true" focusable="false" size={18} />
          )}
        </button>
      </div>
      <button
        type="button"
        disabled={busy || !origin || !email || !password}
        onClick={handleConnect}
        className="w-full rounded-lg bg-primary-container px-4 py-2 font-medium text-on-primary-container disabled:opacity-50"
      >
        {busy ? t('connect.connecting') : t('connect.connectButton')}
      </button>
      {error && (
        <p role="alert" className="mt-3 text-error">
          {mapErrorMessage(error, t)}
        </p>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run entrypoints/popup/ConnectScreen.test.tsx`
Expected: PASS (5 tests).

- [ ] **Step 5: Run full suite and compile check**

Run: `npm test && npm run compile`

- [ ] **Step 6: Commit**

```bash
git add entrypoints/popup/ConnectScreen.tsx entrypoints/popup/ConnectScreen.test.tsx
git commit -m "feat: redesign Connect screen (labeled fields, password visibility toggle, translated copy)"
```

---

### Task 8: VaultScreen redesign

**Files:**
- Modify: `entrypoints/popup/VaultScreen.tsx`, `entrypoints/popup/VaultScreen.test.tsx`

**Interfaces:**
- Consumes: `mapErrorMessage(code, t)` (Task 3), `initI18n` (Task 3), `axe` (Task 4).

- [ ] **Step 1: Write the failing test**

`entrypoints/popup/VaultScreen.test.tsx` (replaces the existing v1 version):

```tsx
import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { axe } from 'vitest-axe';

const sendMessage = vi.fn();
const tabsQuery = vi.fn();
const executeScript = vi.fn();
vi.mock('wxt/browser', () => ({
  browser: {
    runtime: { sendMessage },
    tabs: { query: tabsQuery },
    scripting: { executeScript },
  },
}));

import { initI18n } from './i18n';
import { VaultScreen } from './VaultScreen';

beforeAll(async () => {
  await initI18n();
  Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } });
});

beforeEach(() => {
  vi.clearAllMocks();
  tabsQuery.mockResolvedValue([{ id: 1, url: 'https://example.com/login' }]);
});

describe('VaultScreen', () => {
  it('lists only credentials matching the active tab hostname', async () => {
    sendMessage.mockResolvedValue({
      type: 'vault',
      credentials: [
        { id: '1', service: 'Example', url: 'https://example.com', username: 'alice', folderId: 'f1' },
        { id: '2', service: 'Other', url: 'https://other.com', username: 'bob', folderId: 'f1' },
      ],
      folders: [{ id: 'f1', label: 'General' }],
    });

    render(<VaultScreen />);

    await waitFor(() => expect(screen.getByText('alice')).toBeInTheDocument());
    expect(screen.queryByText('bob')).not.toBeInTheDocument();
  });

  it('shows a helpful empty state when nothing matches', async () => {
    sendMessage.mockResolvedValue({ type: 'vault', credentials: [], folders: [{ id: 'f1', label: 'General' }] });
    render(<VaultScreen />);
    await waitFor(() => expect(screen.getByText('No saved passwords for this site')).toBeInTheDocument());
  });

  it('injects fillFormInPage into the active tab on Fill', async () => {
    sendMessage.mockResolvedValue({
      type: 'vault',
      credentials: [{ id: '1', service: 'Example', url: 'https://example.com', username: 'alice', password: 'pw1', folderId: 'f1' }],
      folders: [{ id: 'f1', label: 'General' }],
    });
    executeScript.mockResolvedValue([{ result: true }]);

    render(<VaultScreen />);
    await waitFor(() => screen.getByText('alice'));
    fireEvent.click(screen.getByRole('button', { name: 'Fill' }));

    await waitFor(() => expect(executeScript).toHaveBeenCalledWith(expect.objectContaining({ target: { tabId: 1 } })));
  });

  it('copies the credential password to the clipboard', async () => {
    sendMessage.mockResolvedValue({
      type: 'vault',
      credentials: [{ id: '1', service: 'Example', url: 'https://example.com', username: 'alice', password: 'pw1', folderId: 'f1' }],
      folders: [{ id: 'f1', label: 'General' }],
    });

    render(<VaultScreen />);
    await waitFor(() => screen.getByText('alice'));
    fireEvent.click(screen.getByRole('button', { name: 'Copy password' }));

    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('pw1');
  });

  it('generates a password on Generate', async () => {
    sendMessage.mockResolvedValue({ type: 'vault', credentials: [], folders: [{ id: 'f1', label: 'General' }] });
    render(<VaultScreen />);
    await waitFor(() => screen.getByRole('button', { name: /generate password/i }));
    fireEvent.click(screen.getByRole('button', { name: /generate password/i }));
    await waitFor(() => expect(screen.getByTestId('generated-password').textContent).toHaveLength(24));
  });

  it('shows a save-success confirmation', async () => {
    sendMessage
      .mockResolvedValueOnce({ type: 'vault', credentials: [], folders: [{ id: 'f1', label: 'General' }] })
      .mockResolvedValueOnce({ type: 'saveResult', ok: true })
      .mockResolvedValueOnce({ type: 'vault', credentials: [], folders: [{ id: 'f1', label: 'General' }] });
    executeScript.mockResolvedValue([{ result: { username: 'alice', password: 'pw1' } }]);

    render(<VaultScreen />);
    await waitFor(() => screen.getByRole('button', { name: /save to vault/i }));
    fireEvent.click(screen.getByRole('button', { name: /save to vault/i }));

    await waitFor(() => expect(screen.getByText('Saved to your vault')).toBeInTheDocument());
  });

  it('has no accessibility violations', async () => {
    sendMessage.mockResolvedValue({ type: 'vault', credentials: [], folders: [{ id: 'f1', label: 'General' }] });
    const { container } = render(<VaultScreen />);
    await waitFor(() => screen.getByText('No saved passwords for this site'));
    expect(await axe(container)).toHaveNoViolations();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run entrypoints/popup/VaultScreen.test.tsx`
Expected: FAIL (old markup has no Copy button, no empty state, no save confirmation).

- [ ] **Step 3: Rewrite `VaultScreen.tsx`**

```tsx
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Copy, Check, RefreshCw } from 'lucide-react';
import { browser } from 'wxt/browser';
import type { Credential, ExtMessage, ExtResponse } from '@/lib/messages';
import { matchCredentialsForHostname, hostnameFromUrl } from '@/lib/matchCredentials';
import { fillFormInPage, readFormInPage } from '@/lib/fillScript';
import { generateCharsetPassword } from '@/lib/passwordGenerator';
import { mapErrorMessage } from '@/lib/errorMessages';

export function VaultScreen() {
  const { t } = useTranslation();
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [hostname, setHostname] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [generated, setGenerated] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    void loadVault();
    void loadActiveHostname();
  }, []);

  async function loadActiveHostname() {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) setHostname(hostnameFromUrl(tab.url));
  }

  async function loadVault() {
    const message: ExtMessage = { type: 'getVault' };
    const response = (await browser.runtime.sendMessage(message)) as ExtResponse;
    if (response.type === 'vault') {
      setCredentials(response.credentials);
    } else if (response.type === 'error') {
      setError(response.error);
    }
  }

  async function handleFill(credential: Credential) {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !credential.password) return;
    await browser.scripting.executeScript({
      target: { tabId: tab.id },
      func: fillFormInPage,
      args: [{ username: credential.username, password: credential.password }],
    });
  }

  async function handleCopy(credential: Credential) {
    if (!credential.password) return;
    await navigator.clipboard.writeText(credential.password);
    setCopiedId(credential.id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  function handleGenerate() {
    setGenerated(generateCharsetPassword({ length: 24, lower: true, upper: true, digits: true, symbols: true }));
  }

  async function handleSave() {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !hostname) return;
    setSaving(true);
    setSaved(false);
    try {
      const [{ result }] = await browser.scripting.executeScript({ target: { tabId: tab.id }, func: readFormInPage });
      const formValues = result ?? { username: '', password: '' };
      const password = generated || formValues.password;
      if (!password) {
        setError('nothing_to_save');
        return;
      }
      const message: ExtMessage = {
        type: 'saveCredential',
        credential: { service: hostname, url: `https://${hostname}`, username: formValues.username, password },
      };
      const response = (await browser.runtime.sendMessage(message)) as ExtResponse;
      if (response.type === 'saveResult' && response.ok) {
        setGenerated('');
        setSaved(true);
        await loadVault();
      } else {
        setError(response.type === 'error' ? response.error : 'save_failed');
      }
    } finally {
      setSaving(false);
    }
  }

  const matched = hostname ? matchCredentialsForHostname(credentials, hostname) : [];

  return (
    <div>
      <h1 className="mb-3 font-headline text-lg font-semibold">{t('vault.title')}</h1>
      {error && (
        <p role="alert" className="mb-3 text-error">
          {mapErrorMessage(error, t)}
        </p>
      )}
      {matched.length === 0 ? (
        <div className="mb-4 rounded-xl border border-outline-variant bg-surface-container-low p-4 text-center">
          <p className="font-medium">{t('vault.emptyStateTitle')}</p>
          <p className="mt-1 text-sm text-on-surface-variant">{t('vault.emptyStateHint')}</p>
        </div>
      ) : (
        <ul className="mb-4 space-y-2">
          {matched.map((c) => (
            <li
              key={c.id}
              className="flex items-center justify-between rounded-lg border border-outline-variant bg-surface-container-low p-3"
            >
              <span className="truncate">{c.username}</span>
              <div className="flex gap-1">
                <button
                  type="button"
                  aria-label={t('vault.copyPasswordButton')}
                  onClick={() => handleCopy(c)}
                  className="text-on-surface-variant"
                >
                  {copiedId === c.id ? (
                    <Check aria-hidden="true" focusable="false" size={18} />
                  ) : (
                    <Copy aria-hidden="true" focusable="false" size={18} />
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => handleFill(c)}
                  className="rounded-lg bg-primary-container px-3 py-1 text-sm font-medium text-on-primary-container"
                >
                  {t('vault.fillButton')}
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
      <button
        type="button"
        onClick={handleGenerate}
        className="mb-2 flex w-full items-center justify-center gap-2 rounded-lg border border-outline-variant px-4 py-2 font-medium"
      >
        <RefreshCw aria-hidden="true" focusable="false" size={16} />
        {t('vault.generateButton')}
      </button>
      {generated && (
        <p
          data-testid="generated-password"
          className="mb-3 rounded-lg bg-surface-container-high p-2 text-center font-mono text-sm"
        >
          {generated}
        </p>
      )}
      <button
        type="button"
        disabled={saving}
        onClick={handleSave}
        className="w-full rounded-lg bg-primary-container px-4 py-2 font-medium text-on-primary-container disabled:opacity-50"
      >
        {saving ? t('vault.saving') : t('vault.saveButton')}
      </button>
      {saved && (
        <p aria-live="polite" className="mt-2 text-center text-sm text-on-surface-variant">
          {t('vault.saveSuccess')}
        </p>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run entrypoints/popup/VaultScreen.test.tsx`
Expected: PASS (7 tests).

- [ ] **Step 5: Run full suite and compile check**

Run: `npm test && npm run compile`

- [ ] **Step 6: Commit**

```bash
git add entrypoints/popup/VaultScreen.tsx entrypoints/popup/VaultScreen.test.tsx
git commit -m "feat: redesign Vault screen (copy button, empty state, save confirmation)"
```

---

### Task 9: Full verification and manual checklist update

**Files:**
- Modify: `docs/MANUAL_E2E_CHECKLIST.md`

**Interfaces:**
- Consumes: everything from Tasks 1-8.

- [ ] **Step 1: Run the full automated suite**

Run: `npm test`
Expected: every test file passes, including all the new axe/i18n/completeness tests from Tasks 3-8.

- [ ] **Step 2: Run compile check**

Run: `npm run compile`
Expected: clean.

- [ ] **Step 3: Verify both production builds**

Run: `npm run build && npm run build:firefox`
Expected: both succeed. Confirm `.output/chrome-mv3/manifest.json` and `.output/firefox-mv3/manifest.json` both reference the new icon set (Task 2) correctly.

- [ ] **Step 4: Update the manual checklist**

Add these items to `docs/MANUAL_E2E_CHECKLIST.md` (after the existing items, renumbering as needed):

```markdown
10. **Visual design** — open the popup in a real browser; confirm it matches the enterprise look (Tailwind styling, navy/blue theme, no unstyled bare elements) and that dark mode follows the OS setting.
11. **Language switcher** — click the globe icon, confirm all 13 languages appear by native name, select a non-English language, and verify the UI text actually changes.
12. **RTL** — select Arabic (العربية) and confirm the entire popup layout mirrors correctly (icons, alignment, text direction), not just the text itself.
13. **Password visibility toggle** — on the Connect screen, confirm the eye icon reveals/hides the typed master password.
14. **Copy password** — on the Vault screen, click the copy icon next to a saved credential and confirm the password lands on the system clipboard.
15. **Toolbar icon** — confirm the browser toolbar shows the real PWDnow shield icon (not a generic placeholder) after loading the unpacked extension.
```

- [ ] **Step 5: Commit**

```bash
git add docs/MANUAL_E2E_CHECKLIST.md
git commit -m "docs: update manual E2E checklist for the UI/i18n/a11y redesign"
```
