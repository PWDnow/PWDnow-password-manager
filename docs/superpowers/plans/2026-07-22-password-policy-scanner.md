# In-Page Password Policy Scanner & Suggestion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Tasks in this plan are prefixed **"PS-Task N"** (Password Scanner) to disambiguate from the prior "Task N" (v1 extension) and "UI-Task N" (enterprise UI/i18n/a11y) plans already completed in this repo — see `.superpowers/sdd/progress.md`.

**Goal:** While browsing any website, automatically detect a new-password field (signup/change-password, not login), parse that site's own password rules from HTML attributes and nearby text (in any of 13 languages), and show an inline banner suggesting a compliant strong password that can be filled and optionally saved to the vault with one click.

**Architecture:** A persistent WXT content script (`entrypoints/content/index.tsx`, `matches: ['<all_urls>']`) runs an initial DOM scan plus a `MutationObserver`. Pure, DOM-independent logic (policy parsing, generation) lives in `lib/`; DOM-touching logic (field classification, text collection) lives in `lib/formDetector.ts`; the banner is a React component mounted into a closed-mode Shadow DOM root. A new `entrypoints/options/` page hosts the two new settings. No changes to v1's or the UI-overhaul's existing login/vault/fill/generate/save logic.

**Tech Stack:** WXT (TypeScript, Manifest V3), React 19, react-i18next + i18next (bundled resources), Tailwind CSS v4, Vitest 4 (`test.projects`: node vs jsdom), `@testing-library/react`, `vitest-axe`, `lucide-react`.

## Global Constraints

- Repo: `/home/pwd-vm/Documents/PWDnow_extension`, standalone git repo, branch `main`, currently at commit `4d4bc19` (115/115 tests passing, `tsc --noEmit` clean). Every task must leave the repo in this same green state.
- `vi.hoisted()` is required whenever a `vi.mock()` factory references a bare top-level `const` (Vitest 4 TDZ/hoisting bug already hit repeatedly in this repo) — apply it in every new test file that mocks `wxt/browser`.
- `@testing-library/jest-dom/vitest`, RTL `cleanup()`, and `vitest-axe`'s matcher wiring are already centralized in `vitest.setup.ts` — new jsdom test files do not need to re-import these.
- Every new/changed popup-style entrypoint (options page, content-script banner) that renders translated text **must** gate its render on `initI18n()` resolving first, exactly like the fix in `entrypoints/popup/main.tsx` (commit `4d4bc19`) — the whole point of PS-Task 1 is to make that pattern reusable. Never skip this; it is the exact regression class the final review of the prior plan caught.
- All 13 locale codes, in this exact order, appear everywhere language lists are iterated: `en, fr, es, de, it, pt, ru, ar, hi, zh, ja, ko, id` (matches `lib/i18n.ts`'s `SUPPORTED_LANGUAGES`).
- New permission: `host_permissions: ["<all_urls>"]` must be added to `wxt.config.ts`'s `manifest` (PS-Task 9) — this is a deliberate, spec-approved change, not an oversight to flag.
- No change to `lib/crypto.ts`, `lib/serverClient.ts`, `lib/session.ts`'s existing exported behavior, or any v1/UI-overhaul component's existing behavior.

---

### PS-Task 1: Relocate the i18n runtime and locale files out of `entrypoints/popup`

The i18n bootstrap (`entrypoints/popup/i18n.ts`) and the 13 locale JSON files are currently popup-exclusive, but PS-Task 7 (options page) and PS-Task 9 (content script) each need their own `initI18n()`/`changeLanguage()` call against the same shared resources. This task is a pure mechanical relocation — no behavior change, verified by the fact that all currently-passing tests still pass afterward with only import paths changed.

**Files:**
- Move: `entrypoints/popup/i18n.ts` → `lib/i18nRuntime.ts` (contents unchanged — its own imports, e.g. `from '@/lib/i18n'` and `from './locales/en.json'`, remain valid because `lib/locales/` sits at the same relative position under `lib/` as `entrypoints/popup/locales/` did under `entrypoints/popup/`)
- Move: `entrypoints/popup/locales/` (all 13 `*.json` files + `locales.test.ts`) → `lib/locales/` (whole directory, contents unchanged — its internal imports like `from './en.json'` remain valid since only the parent directory moved)
- Modify: `entrypoints/popup/LanguageSwitcher.tsx` (import path only)
- Modify: `entrypoints/popup/main.tsx` (import path only)
- Modify: `entrypoints/popup/App.test.tsx`, `entrypoints/popup/ConnectScreen.test.tsx`, `entrypoints/popup/VaultScreen.test.tsx`, `entrypoints/popup/LanguageSwitcher.test.tsx` (import path only, each has a `beforeAll(async () => { await initI18n(); })`)

**Interfaces:**
- Produces: `lib/i18nRuntime.ts` exporting `initI18n(): Promise<void>`, `changeLanguage(lang: LanguageCode): Promise<void>`, `applyDocumentDirection(lang: string): void`, `SUPPORTED_LANGUAGES` (re-exported from `lib/i18n.ts`), and default-exports the `i18n` singleton — identical exports to the old `entrypoints/popup/i18n.ts`, just at a new import path `@/lib/i18nRuntime`.
- Produces: `lib/locales/{en,fr,es,de,it,pt,ru,ar,hi,zh,ja,ko,id}.json` — identical content and shape to before, new location `@/lib/locales/<code>.json`.

- [ ] **Step 1: Move the files with git mv (preserves history)**

```bash
cd /home/pwd-vm/Documents/PWDnow_extension
git mv entrypoints/popup/i18n.ts lib/i18nRuntime.ts
git mv entrypoints/popup/locales lib/locales
```

- [ ] **Step 2: Update the four import sites**

In `entrypoints/popup/LanguageSwitcher.tsx`, change:
```ts
import { changeLanguage } from './i18n';
```
to:
```ts
import { changeLanguage } from '@/lib/i18nRuntime';
```

In `entrypoints/popup/main.tsx`, change:
```ts
import { initI18n } from './i18n';
```
to:
```ts
import { initI18n } from '@/lib/i18nRuntime';
```

In each of `entrypoints/popup/App.test.tsx`, `entrypoints/popup/ConnectScreen.test.tsx`, `entrypoints/popup/VaultScreen.test.tsx`, `entrypoints/popup/LanguageSwitcher.test.tsx`, change:
```ts
import { initI18n } from './i18n';
```
to:
```ts
import { initI18n } from '@/lib/i18nRuntime';
```

- [ ] **Step 3: Run the full test suite and typecheck to verify no behavior changed**

Run: `npm test && npx tsc --noEmit`
Expected: `Test Files 18 passed (18)`, `Tests 115 passed (115)`, no tsc output (clean).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: relocate i18n runtime and locales from popup to lib/

Popup, the new options page (PS-Task 7), and the new content script
(PS-Task 9) each need their own initI18n() call against the same shared
resources — this was popup-exclusive before. Mechanical move, no
behavior change (verified: all 115 tests still pass)."
```

---

### PS-Task 2: Extract `generateCharsetPasswordRaw` and export the character sets in `lib/passwordGenerator.ts`

`lib/passwordGenerator.ts`'s existing `generateCharsetPassword` hard-validates length to 8–64, which is correct for the popup's manual Generate feature but too narrow for arbitrary site policies (PS-Task 3 needs to generate passwords for sites that require e.g. max 12 or allow up to 100 characters). Extract the core sampling loop into an unchecked helper, and export the character-set constants so `lib/passwordPolicy.ts` (PS-Task 3) can build charsets from the exact same source data rather than duplicating it.

**Files:**
- Modify: `lib/passwordGenerator.ts`
- Modify: `lib/passwordGenerator.test.ts` (add new tests; existing tests must keep passing unchanged)

**Interfaces:**
- Produces: `export const LOWER: string`, `export const UPPER: string`, `export const DIGITS: string`, `export const SYMBOLS: string` (previously module-private).
- Produces: `export function generateCharsetPasswordRaw(length: number, charset: string): string` — no length bounds validation (caller's responsibility), throws only if `charset` is empty.
- Consumed by: PS-Task 3's `lib/passwordPolicy.ts` (`generateCompliantPassword`).

- [ ] **Step 1: Write the failing tests**

Add to `lib/passwordGenerator.test.ts`:

```ts
import { generateCharsetPasswordRaw, LOWER, UPPER, DIGITS, SYMBOLS } from './passwordGenerator';

describe('generateCharsetPasswordRaw', () => {
  it('produces a string of the exact requested length, including lengths outside 8-64', () => {
    expect(generateCharsetPasswordRaw(3, LOWER)).toHaveLength(3);
    expect(generateCharsetPasswordRaw(100, LOWER)).toHaveLength(100);
  });

  it('only uses characters from the provided charset', () => {
    const result = generateCharsetPasswordRaw(50, DIGITS);
    expect([...result].every((c) => DIGITS.includes(c))).toBe(true);
  });

  it('returns an empty string for length 0', () => {
    expect(generateCharsetPasswordRaw(0, LOWER)).toBe('');
  });

  it('throws if the charset is empty', () => {
    expect(() => generateCharsetPasswordRaw(5, '')).toThrow();
  });
});

describe('exported character sets', () => {
  it('exposes the same character sets used internally', () => {
    expect(LOWER).toBe('abcdefghijklmnopqrstuvwxyz');
    expect(UPPER).toBe('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    expect(DIGITS).toBe('0123456789');
    expect(SYMBOLS).toBe('!@#$%^&*()_+-=[]{}|;:,.<>?');
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run lib/passwordGenerator.test.ts`
Expected: FAIL — `generateCharsetPasswordRaw`, `LOWER`, `UPPER`, `DIGITS`, `SYMBOLS` are not exported yet.

- [ ] **Step 3: Implement**

Replace the top of `lib/passwordGenerator.ts` and `generateCharsetPassword`'s body:

```ts
export const LOWER = 'abcdefghijklmnopqrstuvwxyz';
export const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
export const DIGITS = '0123456789';
export const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';

export interface CharsetOptions {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
}

export interface PassphraseOptions {
  wordCount: number;
  capitalizeFirst: boolean;
  injectDigit: boolean;
  injectSymbol: boolean;
}

/** Rejection-sampling uniform random integer in [0, maxExclusive) - avoids modulo bias. */
export function secureRandInt(maxExclusive: number): number {
  if (maxExclusive <= 0) throw new Error('secureRandInt: maxExclusive must be > 0');
  const bytesNeeded = Math.max(1, Math.ceil(Math.log2(maxExclusive) / 8));
  const range = 256 ** bytesNeeded;
  const maxValid = Math.floor(range / maxExclusive) * maxExclusive;
  const buf = new Uint8Array(bytesNeeded);
  let value: number;
  do {
    crypto.getRandomValues(buf);
    value = buf.reduce((acc, b) => acc * 256 + b, 0);
  } while (value >= maxValid);
  return value % maxExclusive;
}

/**
 * Unchecked core sampling loop shared by `generateCharsetPassword` (which
 * enforces the 8-64 bound appropriate for the popup's manual Generate
 * screen) and `generateCompliantPassword` in `lib/passwordPolicy.ts` (which
 * must support arbitrary site-defined length bounds instead).
 */
export function generateCharsetPasswordRaw(length: number, charset: string): string {
  if (!charset) throw new Error('generateCharsetPasswordRaw: charset must not be empty');
  let out = '';
  for (let i = 0; i < length; i++) {
    out += charset[secureRandInt(charset.length)];
  }
  return out;
}

export function generateCharsetPassword(opts: CharsetOptions): string {
  const { length, lower, upper, digits, symbols } = opts;
  if (length < 8 || length > 64) throw new Error('generateCharsetPassword: length must be between 8 and 64');
  let charset = '';
  if (lower) charset += LOWER;
  if (upper) charset += UPPER;
  if (digits) charset += DIGITS;
  if (symbols) charset += SYMBOLS;
  if (!charset) throw new Error('generateCharsetPassword: at least one character class must be enabled');
  return generateCharsetPasswordRaw(length, charset);
}
```

(`generatePassphrase` below it is unchanged.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/passwordGenerator.test.ts`
Expected: all tests PASS, including the pre-existing ones (unchanged behavior).

- [ ] **Step 5: Commit**

```bash
git add lib/passwordGenerator.ts lib/passwordGenerator.test.ts
git commit -m "refactor: extract generateCharsetPasswordRaw, export char sets

generateCharsetPassword's 8-64 bound is correct for the popup's manual
Generate screen but too narrow for arbitrary site password policies.
PS-Task 3's generateCompliantPassword needs the unchecked core loop and
the same character-set data, not a duplicate copy."
```

---

### PS-Task 3: `lib/passwordPolicy.ts` — types, attribute parsing, English text parsing, merge, and generation

The core policy-resolution module: pure functions, no DOM dependency (DOM reading happens in PS-Task 5's `lib/formDetector.ts`, which calls into this module). This task covers the type definitions, HTML-attribute parsing, English text-pattern parsing, the merge algorithm, and compliant-password generation. PS-Task 4 adds the other 12 languages' text patterns on top of the same `PATTERNS` structure this task establishes.

**Files:**
- Create: `lib/passwordPolicy.ts`
- Create: `lib/passwordPolicy.test.ts`

**Interfaces:**
- Consumes: `LOWER, UPPER, DIGITS, SYMBOLS, secureRandInt, generateCharsetPasswordRaw` from `@/lib/passwordGenerator` (PS-Task 2). `LanguageCode` from `@/lib/i18n`.
- Produces: `export interface PasswordPolicy { minLength: number; maxLength: number; requireLower: boolean; requireUpper: boolean; requireDigit: boolean; requireSymbol: boolean; allowedSymbols?: string }`.
- Produces: `export interface PartialPolicy` (all fields of `PasswordPolicy` optional).
- Produces: `export interface AttributeHints { minLength?: number; maxLength?: number; pattern?: string }`.
- Produces: `export function parsePolicyFromAttributes(hints: AttributeHints): PartialPolicy`.
- Produces: `export function parsePolicyFromText(text: string, lang: LanguageCode): PartialPolicy` — used by PS-Task 5.
- Produces: `export function mergePolicies(...parts: PartialPolicy[]): PasswordPolicy` — used by PS-Task 5.
- Produces: `export function generateCompliantPassword(policy: PasswordPolicy): string` — used by PS-Task 9.
- Produces: `export const GENERIC_FALLBACK_POLICY: PasswordPolicy` (16 chars, all four classes required) — the safe default `mergePolicies` falls back to when nothing else was detected.

- [ ] **Step 1: Write the failing tests**

Create `lib/passwordPolicy.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import {
  parsePolicyFromAttributes,
  parsePolicyFromText,
  mergePolicies,
  generateCompliantPassword,
  GENERIC_FALLBACK_POLICY,
  type PasswordPolicy,
} from './passwordPolicy';

describe('parsePolicyFromAttributes', () => {
  it('reads minLength and maxLength when present', () => {
    expect(parsePolicyFromAttributes({ minLength: 8, maxLength: 100 })).toEqual({
      minLength: 8,
      maxLength: 100,
    });
  });

  it('ignores unset (-1 style) or zero values', () => {
    expect(parsePolicyFromAttributes({ minLength: 0, maxLength: undefined })).toEqual({});
  });

  it('detects common lookahead-pattern character-class requirements', () => {
    const pattern = '(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{8,}';
    expect(parsePolicyFromAttributes({ pattern })).toEqual({
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });

  it('returns an empty object for a pattern with no recognizable lookaheads', () => {
    expect(parsePolicyFromAttributes({ pattern: '.{8,}' })).toEqual({});
  });
});

describe('parsePolicyFromText (English)', () => {
  it('parses a length range', () => {
    const result = parsePolicyFromText('Password must be 8-100 characters long.', 'en');
    expect(result.minLength).toBe(8);
    expect(result.maxLength).toBe(100);
  });

  it('parses "at least N characters"', () => {
    const result = parsePolicyFromText('Must be at least 12 characters.', 'en');
    expect(result.minLength).toBe(12);
    expect(result.maxLength).toBeUndefined();
  });

  it('parses all four character-class requirements from one sentence', () => {
    const text =
      'Your password must be 8-100 characters and include an uppercase letter, a lowercase letter, a number, and a special character.';
    expect(parsePolicyFromText(text, 'en')).toEqual({
      minLength: 8,
      maxLength: 100,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });

  it('returns an empty object when no recognizable phrasing is present', () => {
    expect(parsePolicyFromText('Enter your password below.', 'en')).toEqual({});
  });
});

describe('mergePolicies', () => {
  it('falls back to GENERIC_FALLBACK_POLICY when nothing was specified', () => {
    expect(mergePolicies({}, {})).toEqual(GENERIC_FALLBACK_POLICY);
  });

  it('prefers the first-defined minLength/maxLength across parts (attributes before text)', () => {
    const result = mergePolicies({ minLength: 10, maxLength: 20 }, { minLength: 8, maxLength: 100 });
    expect(result.minLength).toBe(10);
    expect(result.maxLength).toBe(20);
  });

  it('combines requirement flags additively across parts (any true wins)', () => {
    const result = mergePolicies({ requireUpper: true }, { requireDigit: true });
    expect(result.requireUpper).toBe(true);
    expect(result.requireDigit).toBe(true);
    expect(result.requireLower).toBe(false);
    expect(result.requireSymbol).toBe(false);
  });

  it('clamps maxLength up to minLength if a source gave a contradictory maxLength', () => {
    const result = mergePolicies({ minLength: 20, maxLength: 10 });
    expect(result.maxLength).toBeGreaterThanOrEqual(result.minLength);
  });
});

describe('generateCompliantPassword', () => {
  function satisfies(password: string, policy: PasswordPolicy): boolean {
    if (password.length < Math.max(4, Math.min(policy.minLength, policy.maxLength))) return false;
    if (password.length > Math.min(128, Math.max(policy.minLength, policy.maxLength))) return false;
    const symbolSet = policy.allowedSymbols || '!@#$%^&*()_+-=[]{}|;:,.<>?';
    if (policy.requireLower && ![...password].some((c) => /[a-z]/.test(c))) return false;
    if (policy.requireUpper && ![...password].some((c) => /[A-Z]/.test(c))) return false;
    if (policy.requireDigit && ![...password].some((c) => /\d/.test(c))) return false;
    if (policy.requireSymbol && ![...password].some((c) => symbolSet.includes(c))) return false;
    return true;
  }

  it('generates a password satisfying a typical policy, repeatedly', () => {
    const policy: PasswordPolicy = {
      minLength: 12,
      maxLength: 20,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    };
    for (let i = 0; i < 50; i++) {
      const password = generateCompliantPassword(policy);
      expect(satisfies(password, policy)).toBe(true);
    }
  });

  it('respects a very restrictive maxLength by dropping symbol, then digit, then upper before giving up', () => {
    const policy: PasswordPolicy = {
      minLength: 2,
      maxLength: 2,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    };
    const password = generateCompliantPassword(policy);
    expect(password.length).toBeLessThanOrEqual(2);
    expect(password.length).toBeGreaterThan(0);
  });

  it('respects a custom allowedSymbols set', () => {
    const policy: PasswordPolicy = {
      minLength: 16,
      maxLength: 16,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
      allowedSymbols: '!?',
    };
    for (let i = 0; i < 20; i++) {
      const password = generateCompliantPassword(policy);
      expect(satisfies(password, policy)).toBe(true);
      expect([...password].every((c) => /[a-zA-Z0-9]/.test(c) || '!?'.includes(c))).toBe(true);
    }
  });

  it('never exceeds the absolute 128-character ceiling even for an extreme maxLength', () => {
    const policy: PasswordPolicy = {
      minLength: 16,
      maxLength: 10000,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    };
    expect(generateCompliantPassword(policy).length).toBeLessThanOrEqual(128);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run lib/passwordPolicy.test.ts`
Expected: FAIL — `lib/passwordPolicy.ts` does not exist yet.

- [ ] **Step 3: Implement**

Create `lib/passwordPolicy.ts`:

```ts
import { LOWER, UPPER, DIGITS, SYMBOLS, secureRandInt, generateCharsetPasswordRaw } from './passwordGenerator';
import type { LanguageCode } from './i18n';

export interface PasswordPolicy {
  minLength: number;
  maxLength: number;
  requireLower: boolean;
  requireUpper: boolean;
  requireDigit: boolean;
  requireSymbol: boolean;
  allowedSymbols?: string;
}

export interface PartialPolicy {
  minLength?: number;
  maxLength?: number;
  requireLower?: boolean;
  requireUpper?: boolean;
  requireDigit?: boolean;
  requireSymbol?: boolean;
  allowedSymbols?: string;
}

export interface AttributeHints {
  minLength?: number;
  maxLength?: number;
  pattern?: string;
}

export const GENERIC_FALLBACK_POLICY: PasswordPolicy = {
  minLength: 16,
  maxLength: 16,
  requireLower: true,
  requireUpper: true,
  requireDigit: true,
  requireSymbol: true,
};

const ABSOLUTE_MIN_LENGTH = 4;
const ABSOLUTE_MAX_LENGTH = 128;

// Common lookahead-based password-validation pattern conventions, e.g.
// `(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9])` — a widely-used
// hand-rolled convention for HTML `pattern` attributes, not a full regex
// parser. A pattern using a different convention simply yields no signal
// here and falls through to text-based / fallback detection instead.
const LOOKAHEAD_LOWER = /\(\?=\.\*\[a-z\]\)/;
const LOOKAHEAD_UPPER = /\(\?=\.\*\[A-Z\]\)/;
const LOOKAHEAD_DIGIT = /\(\?=\.\*(?:\\d|\[0-9\])\)/;
const LOOKAHEAD_SYMBOL = /\(\?=\.\*\[\^[^\]]*\]\)/;

export function parsePolicyFromAttributes(hints: AttributeHints): PartialPolicy {
  const policy: PartialPolicy = {};
  if (hints.minLength !== undefined && hints.minLength > 0) policy.minLength = hints.minLength;
  if (hints.maxLength !== undefined && hints.maxLength > 0) policy.maxLength = hints.maxLength;
  if (hints.pattern) {
    if (LOOKAHEAD_LOWER.test(hints.pattern)) policy.requireLower = true;
    if (LOOKAHEAD_UPPER.test(hints.pattern)) policy.requireUpper = true;
    if (LOOKAHEAD_DIGIT.test(hints.pattern)) policy.requireDigit = true;
    if (LOOKAHEAD_SYMBOL.test(hints.pattern)) policy.requireSymbol = true;
  }
  return policy;
}

interface TextPatternSet {
  lengthRange: RegExp;
  minLengthOnly: RegExp;
  lower: RegExp;
  upper: RegExp;
  digit: RegExp;
  symbol: RegExp;
}

// English pattern set. PS-Task 4 adds the other 12 languages to this same
// map — do not restructure `TextPatternSet` or `PATTERNS` there, only add
// entries.
export const PATTERNS: Partial<Record<LanguageCode, TextPatternSet>> = {
  en: {
    lengthRange: /(\d{1,3})\s*(?:-|to|and)\s*(\d{1,3})\s*characters?/iu,
    minLengthOnly: /at least\s*(\d{1,3})\s*characters?/iu,
    lower: /lower[\s-]?case/iu,
    upper: /upper[\s-]?case/iu,
    digit: /\bnumber\b|\bdigit\b/iu,
    symbol: /special character|\bsymbol\b/iu,
  },
};

export function parsePolicyFromText(text: string, lang: LanguageCode): PartialPolicy {
  const patterns = PATTERNS[lang] ?? PATTERNS.en!;
  const policy: PartialPolicy = {};

  const rangeMatch = text.match(patterns.lengthRange);
  if (rangeMatch) {
    policy.minLength = parseInt(rangeMatch[1], 10);
    policy.maxLength = parseInt(rangeMatch[2], 10);
  } else {
    const minMatch = text.match(patterns.minLengthOnly);
    if (minMatch) policy.minLength = parseInt(minMatch[1], 10);
  }

  if (patterns.lower.test(text)) policy.requireLower = true;
  if (patterns.upper.test(text)) policy.requireUpper = true;
  if (patterns.digit.test(text)) policy.requireDigit = true;
  if (patterns.symbol.test(text)) policy.requireSymbol = true;

  return policy;
}

export function mergePolicies(...parts: PartialPolicy[]): PasswordPolicy {
  let minLength: number | undefined;
  let maxLength: number | undefined;
  let allowedSymbols: string | undefined;
  let requireLower = false;
  let requireUpper = false;
  let requireDigit = false;
  let requireSymbol = false;

  for (const part of parts) {
    if (minLength === undefined && part.minLength !== undefined) minLength = part.minLength;
    if (maxLength === undefined && part.maxLength !== undefined) maxLength = part.maxLength;
    if (allowedSymbols === undefined && part.allowedSymbols !== undefined) allowedSymbols = part.allowedSymbols;
    if (part.requireLower) requireLower = true;
    if (part.requireUpper) requireUpper = true;
    if (part.requireDigit) requireDigit = true;
    if (part.requireSymbol) requireSymbol = true;
  }

  const resolvedMin = minLength ?? GENERIC_FALLBACK_POLICY.minLength;
  let resolvedMax = maxLength ?? Math.max(resolvedMin, GENERIC_FALLBACK_POLICY.maxLength);
  if (resolvedMax < resolvedMin) resolvedMax = resolvedMin;

  const anyRequirementSpecified = requireLower || requireUpper || requireDigit || requireSymbol;

  return {
    minLength: resolvedMin,
    maxLength: resolvedMax,
    requireLower: anyRequirementSpecified ? requireLower : true,
    requireUpper: anyRequirementSpecified ? requireUpper : true,
    requireDigit: anyRequirementSpecified ? requireDigit : true,
    requireSymbol: anyRequirementSpecified ? requireSymbol : true,
    allowedSymbols,
  };
}

export function generateCompliantPassword(policy: PasswordPolicy): string {
  const symbolSet = policy.allowedSymbols && policy.allowedSymbols.length > 0 ? policy.allowedSymbols : SYMBOLS;
  // Resolve maxLength from the *unfloored* policy.minLength first (only
  // pulling maxLength up if the policy itself is contradictory, min > max —
  // mirroring mergePolicies' own "clamps maxLength up to minLength" contract).
  // ABSOLUTE_MIN_LENGTH must never leak into this step: doing `Math.max(floor,
  // policy.minLength)` before computing maxLength let a floor of 4 silently
  // override an explicit, tighter policy.maxLength of 2 — failing the
  // restrictive-maxLength test below, which expects length <= 2.
  const maxLength = Math.min(ABSOLUTE_MAX_LENGTH, Math.max(policy.minLength, policy.maxLength));
  const minLength = Math.min(maxLength, Math.max(ABSOLUTE_MIN_LENGTH, policy.minLength));

  let requiredCharsets: string[] = [];
  if (policy.requireLower) requiredCharsets.push(LOWER);
  if (policy.requireUpper) requiredCharsets.push(UPPER);
  if (policy.requireDigit) requiredCharsets.push(DIGITS);
  if (policy.requireSymbol) requiredCharsets.push(symbolSet);
  if (requiredCharsets.length === 0) requiredCharsets = [LOWER];

  // A maxLength too small to fit one character from every required class is
  // a contradictory policy — satisfy as many classes as possible, dropping
  // the least-critical ones first (symbol, then digit, then upper), never
  // dropping below a single charset.
  const dropPriority = [symbolSet, DIGITS, UPPER];
  for (const toDrop of dropPriority) {
    if (requiredCharsets.length <= maxLength) break;
    if (requiredCharsets.length > 1) {
      requiredCharsets = requiredCharsets.filter((c) => c !== toDrop);
    }
  }

  const targetLength = Math.min(maxLength, Math.max(minLength, requiredCharsets.length));
  const combinedCharset = Array.from(new Set(requiredCharsets.join(''))).join('');

  // Guarantee at least one character from each surviving required class,
  // then fill the remainder from the combined charset, then shuffle so the
  // guaranteed characters aren't always in the first positions.
  const guaranteed = requiredCharsets.map((charset) => charset[secureRandInt(charset.length)]);
  const fillLength = targetLength - guaranteed.length;
  const fill = generateCharsetPasswordRaw(fillLength, combinedCharset).split('');
  const chars = [...guaranteed, ...fill];

  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureRandInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join('');
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/passwordPolicy.test.ts`
Expected: all tests PASS.

- [ ] **Step 5: Run the full suite and typecheck**

Run: `npm test && npx tsc --noEmit`
Expected: `Tests 115 passed` plus the new `lib/passwordPolicy.test.ts` tests, all passing; tsc clean.

- [ ] **Step 6: Commit**

```bash
git add lib/passwordPolicy.ts lib/passwordPolicy.test.ts
git commit -m "feat: add lib/passwordPolicy.ts (types, attribute+English text parsing, merge, generation)

Pure, DOM-independent policy resolution: parse minlength/maxlength/pattern
attributes and English rule-phrasing, merge multiple partial sources into
a resolved PasswordPolicy, and generate a password guaranteed to satisfy
it. PS-Task 4 adds the other 12 languages' text patterns on top of the
same PATTERNS structure."
```

---

### PS-Task 4: `lib/passwordPolicy.ts` — text patterns for the other 12 languages

Adds `fr, es, de, it, pt, ru, ar, hi, zh, ja, ko, id` entries to the `PATTERNS` map established in PS-Task 3, one comprehensive test phrase per language (matching all four character-class requirements plus a length range, mirroring real signup-page rule text). This is a translation-quality task — the phrases and regex patterns below use real vocabulary for each language's common password-rule phrasing; a native-fluency review pass (as was done for the UI-overhaul's 13 locale files) is expected during this task's review.

**Files:**
- Modify: `lib/passwordPolicy.ts` (add 12 entries to the existing `PATTERNS` map — do not touch the `en` entry or any other exported function from PS-Task 3)
- Modify: `lib/passwordPolicy.test.ts` (add one `describe` block per language)

**Interfaces:**
- Consumes: the `TextPatternSet` interface and `PATTERNS` map shape from PS-Task 3 (add entries only).
- No new exports beyond what PS-Task 3 already produces.

- [ ] **Step 1: Write the failing tests**

Add to `lib/passwordPolicy.test.ts`:

```ts
describe('parsePolicyFromText (other languages)', () => {
  it('parses French', () => {
    const text =
      'Votre mot de passe doit comporter entre 8 et 100 caractères et inclure une majuscule, une minuscule, un chiffre et un caractère spécial.';
    expect(parsePolicyFromText(text, 'fr')).toEqual({
      minLength: 8,
      maxLength: 100,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });

  it('parses Spanish', () => {
    const text =
      'Tu contraseña debe tener entre 8 y 100 caracteres e incluir una mayúscula, una minúscula, un número y un carácter especial.';
    expect(parsePolicyFromText(text, 'es')).toEqual({
      minLength: 8,
      maxLength: 100,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });

  it('parses German', () => {
    const text =
      'Dein Passwort muss 8 bis 100 Zeichen lang sein und einen Großbuchstaben, einen Kleinbuchstabe, eine Zahl und ein Sonderzeichen enthalten.';
    expect(parsePolicyFromText(text, 'de')).toEqual({
      minLength: 8,
      maxLength: 100,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });

  it('parses Italian', () => {
    const text =
      'La password deve avere da 8 a 100 caratteri e includere una maiuscola, una minuscola, un numero e un carattere speciale.';
    expect(parsePolicyFromText(text, 'it')).toEqual({
      minLength: 8,
      maxLength: 100,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });

  it('parses Portuguese', () => {
    const text =
      'Sua senha deve ter entre 8 e 100 caracteres e incluir uma maiúscula, uma minúscula, um número e um caractere especial.';
    expect(parsePolicyFromText(text, 'pt')).toEqual({
      minLength: 8,
      maxLength: 100,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });

  it('parses Russian', () => {
    const text =
      'Пароль должен содержать от 8 до 100 символов и включать заглавную букву, строчную букву, цифру и специальный символ.';
    expect(parsePolicyFromText(text, 'ru')).toEqual({
      minLength: 8,
      maxLength: 100,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });

  it('parses Arabic', () => {
    const text = 'يجب أن تتكون كلمة المرور من 8 إلى 100 حرف وتشمل حرف كبير وحرف صغير ورقم ورمز خاص.';
    expect(parsePolicyFromText(text, 'ar')).toEqual({
      minLength: 8,
      maxLength: 100,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });

  it('parses Hindi', () => {
    const text =
      'आपका पासवर्ड 8 से 100 अक्षर का होना चाहिए और इसमें बड़ा अक्षर, छोटा अक्षर, अंक और विशेष चिह्न शामिल होना चाहिए।';
    expect(parsePolicyFromText(text, 'hi')).toEqual({
      minLength: 8,
      maxLength: 100,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });

  it('parses Chinese', () => {
    const text = '您的密码必须为8到100个字符，并包含大写字母、小写字母、数字和特殊字符。';
    expect(parsePolicyFromText(text, 'zh')).toEqual({
      minLength: 8,
      maxLength: 100,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });

  it('parses Japanese', () => {
    const text = 'パスワードは8文字から100文字で、大文字、小文字、数字、特殊文字を含める必要があります。';
    expect(parsePolicyFromText(text, 'ja')).toEqual({
      minLength: 8,
      maxLength: 100,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });

  it('parses Korean', () => {
    const text = '비밀번호는 8자에서 100자 사이여야 하며 대문자, 소문자, 숫자, 특수 문자를 포함해야 합니다.';
    expect(parsePolicyFromText(text, 'ko')).toEqual({
      minLength: 8,
      maxLength: 100,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });

  it('parses Indonesian', () => {
    const text =
      'Kata sandi Anda harus terdiri dari 8 hingga 100 karakter dan menyertakan huruf besar, huruf kecil, angka, dan karakter khusus.';
    expect(parsePolicyFromText(text, 'id')).toEqual({
      minLength: 8,
      maxLength: 100,
      requireLower: true,
      requireUpper: true,
      requireDigit: true,
      requireSymbol: true,
    });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run lib/passwordPolicy.test.ts`
Expected: FAIL — the 12 new language tests fail (no `PATTERNS` entries yet for `fr`/`es`/etc., so `parsePolicyFromText` falls back to the English patterns and doesn't match the non-English text).

- [ ] **Step 3: Implement — add 12 entries to the `PATTERNS` map in `lib/passwordPolicy.ts`**

Add after the `en` entry (inside the same `PATTERNS` object, do not remove the trailing `};`):

```ts
  fr: {
    lengthRange: /(\d{1,3})\s*(?:à|et|-)\s*(\d{1,3})\s*caractères/iu,
    minLengthOnly: /au moins\s*(\d{1,3})\s*caractères/iu,
    lower: /minuscule/iu,
    upper: /majuscule/iu,
    digit: /\bchiffre\b|\bnombre\b/iu,
    symbol: /caractère spécial|\bsymbole\b/iu,
  },
  es: {
    lengthRange: /(\d{1,3})\s*(?:a|y|-)\s*(\d{1,3})\s*caracteres/iu,
    minLengthOnly: /al menos\s*(\d{1,3})\s*caracteres/iu,
    lower: /minúscula/iu,
    upper: /mayúscula/iu,
    digit: /\bnúmero\b|\bdígito\b/iu,
    symbol: /carácter especial|\bsímbolo\b/iu,
  },
  de: {
    lengthRange: /(\d{1,3})\s*(?:bis|und|-)\s*(\d{1,3})\s*Zeichen/iu,
    minLengthOnly: /mindestens\s*(\d{1,3})\s*Zeichen/iu,
    lower: /Kleinbuchstabe/iu,
    upper: /Großbuchstabe/iu,
    digit: /\bZahl\b|\bZiffer\b/iu,
    symbol: /Sonderzeichen/iu,
  },
  it: {
    lengthRange: /(\d{1,3})\s*(?:a|e|-)\s*(\d{1,3})\s*caratteri/iu,
    minLengthOnly: /almeno\s*(\d{1,3})\s*caratteri/iu,
    lower: /minuscola/iu,
    upper: /maiuscola/iu,
    digit: /\bnumero\b|\bcifra\b/iu,
    symbol: /carattere speciale|\bsimbolo\b/iu,
  },
  pt: {
    lengthRange: /(\d{1,3})\s*(?:a|e|-)\s*(\d{1,3})\s*caracteres/iu,
    minLengthOnly: /pelo menos\s*(\d{1,3})\s*caracteres/iu,
    lower: /minúscula/iu,
    upper: /maiúscula/iu,
    digit: /\bnúmero\b|\bdígito\b/iu,
    symbol: /caractere especial|\bsímbolo\b/iu,
  },
  ru: {
    lengthRange: /(\d{1,3})\s*(?:-|до|и)\s*(\d{1,3})\s*символ/iu,
    minLengthOnly: /не менее\s*(\d{1,3})\s*символ/iu,
    lower: /строчн\w*\s*букв/iu,
    upper: /заглавн\w*\s*букв/iu,
    digit: /\bцифр\w*/iu,
    symbol: /специальн\w*\s*символ/iu,
  },
  ar: {
    lengthRange: /(\d{1,3})\s*(?:-|إلى|و)\s*(\d{1,3})\s*(?:حرف|أحرف|حروف)/iu,
    minLengthOnly: /على الأقل\s*(\d{1,3})\s*(?:حرف|أحرف|حروف)/iu,
    lower: /حرف صغير|أحرف صغيرة/iu,
    upper: /حرف كبير|أحرف كبيرة/iu,
    digit: /رقم/iu,
    symbol: /رمز خاص|حرف خاص/iu,
  },
  hi: {
    lengthRange: /(\d{1,3})\s*(?:से|-)\s*(\d{1,3})\s*अक्षर/iu,
    minLengthOnly: /कम से कम\s*(\d{1,3})\s*अक्षर/iu,
    lower: /छोटा अक्षर/iu,
    upper: /बड़ा अक्षर/iu,
    digit: /अंक/iu,
    symbol: /विशेष चिह्न|विशेष वर्ण/iu,
  },
  zh: {
    lengthRange: /(\d{1,3})\s*(?:到|至|-)\s*(\d{1,3})\s*个?字符/iu,
    minLengthOnly: /至少\s*(\d{1,3})\s*个?字符/iu,
    lower: /小写字母/iu,
    upper: /大写字母/iu,
    digit: /数字/iu,
    symbol: /特殊字符/iu,
  },
  ja: {
    lengthRange: /(\d{1,3})\s*文字\s*(?:から|-)\s*(\d{1,3})\s*文字/iu,
    minLengthOnly: /少なくとも\s*(\d{1,3})\s*文字/iu,
    lower: /小文字/iu,
    upper: /大文字/iu,
    digit: /数字/iu,
    symbol: /特殊文字|記号/iu,
  },
  ko: {
    lengthRange: /(\d{1,3})\s*자\s*(?:에서|-)\s*(\d{1,3})\s*자/iu,
    minLengthOnly: /최소\s*(\d{1,3})\s*자/iu,
    lower: /소문자/iu,
    upper: /대문자/iu,
    digit: /숫자/iu,
    symbol: /특수\s*문자/iu,
  },
  id: {
    lengthRange: /(\d{1,3})\s*(?:hingga|sampai|-)\s*(\d{1,3})\s*karakter/iu,
    minLengthOnly: /minimal\s*(\d{1,3})\s*karakter/iu,
    lower: /huruf kecil/iu,
    upper: /huruf besar/iu,
    digit: /\bangka\b|\bnomor\b/iu,
    symbol: /karakter khusus/iu,
  },
```

Note the Japanese and Korean `lengthRange` patterns restate the counter word (文字/자) after each number (matching how those languages actually phrase ranges, e.g. "8文字から100文字") rather than once at the end like the other languages — this is a real, deliberate difference, not an inconsistency to fix.

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/passwordPolicy.test.ts`
Expected: all tests PASS, including all 12 new language tests.

- [ ] **Step 5: Run the full suite and typecheck**

Run: `npm test && npx tsc --noEmit`
Expected: all tests pass, tsc clean.

- [ ] **Step 6: Commit**

```bash
git add lib/passwordPolicy.ts lib/passwordPolicy.test.ts
git commit -m "feat: add text-pattern sets for the other 12 languages to passwordPolicy

Extends PATTERNS (established in the previous task) with fr, es, de, it,
pt, ru, ar, hi, zh, ja, ko, id — real vocabulary for common password-rule
phrasing in each language, one comprehensive test phrase per language
covering length range plus all four character-class requirements."
```

---

### PS-Task 5: `lib/formDetector.ts` — signals heuristic, nearby-text collection, policy resolution

The only DOM-touching module besides the content script itself. Classifies whether a password field is a "new password" context (not an ordinary login field), collects the text around it for `parsePolicyFromText`, and ties attribute + text parsing + merge together into one convenience function the content script calls per field.

**Files:**
- Create: `lib/formDetector.ts`
- Create: `lib/formDetector.test.ts`
- Modify: `vitest.config.ts` (this test needs a real DOM — add it to the jsdom project's `include`, and to the node project's `exclude`, mirroring the existing treatment of `lib/fillScript.test.ts` and `lib/matchCredentials.test.ts`)

**Interfaces:**
- Consumes: `parsePolicyFromAttributes, parsePolicyFromText, mergePolicies, type PasswordPolicy` from `@/lib/passwordPolicy` (PS-Task 3/4). `type LanguageCode` from `@/lib/i18n`.
- Produces: `export interface PasswordFieldGroup { passwordInput: HTMLInputElement; confirmInput: HTMLInputElement | null; usernameInput: HTMLInputElement | null }` — used by PS-Task 9.
- Produces: `export function isNewPasswordContext(input: HTMLInputElement, doc: Document): boolean` — used by PS-Task 9.
- Produces: `export function collectNearbyText(input: HTMLInputElement): string`.
- Produces: `export function findPasswordFieldGroups(doc: Document): PasswordFieldGroup[]` — used by PS-Task 9.
- Produces: `export function resolvePolicyForField(input: HTMLInputElement, lang: LanguageCode): PasswordPolicy` — used by PS-Task 9.

- [ ] **Step 1: Write the failing tests**

Create `lib/formDetector.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { isNewPasswordContext, collectNearbyText, findPasswordFieldGroups, resolvePolicyForField } from './formDetector';

function setDom(html: string): Document {
  document.body.innerHTML = html;
  return document;
}

describe('isNewPasswordContext', () => {
  it('rejects an ordinary login form (single password field, no signals)', () => {
    const doc = setDom(`
      <form>
        <input id="email" type="email" />
        <input id="pw" type="password" autocomplete="current-password" />
        <button>Sign in</button>
      </form>
    `);
    const input = doc.getElementById('pw') as HTMLInputElement;
    expect(isNewPasswordContext(input, doc)).toBe(false);
  });

  it('accepts autocomplete="new-password"', () => {
    const doc = setDom(`<form><input id="pw" type="password" autocomplete="new-password" /></form>`);
    const input = doc.getElementById('pw') as HTMLInputElement;
    expect(isNewPasswordContext(input, doc)).toBe(true);
  });

  it('accepts two adjacent password fields (password + confirm)', () => {
    const doc = setDom(`
      <form>
        <input id="pw" type="password" />
        <input id="pw2" type="password" />
      </form>
    `);
    const input = doc.getElementById('pw') as HTMLInputElement;
    expect(isNewPasswordContext(input, doc)).toBe(true);
  });

  it('accepts nearby signup/registration phrasing', () => {
    const doc = setDom(`
      <form>
        <label for="pw">Choose a password</label>
        <input id="pw" type="password" />
      </form>
    `);
    const input = doc.getElementById('pw') as HTMLInputElement;
    expect(isNewPasswordContext(input, doc)).toBe(true);
  });
});

describe('collectNearbyText', () => {
  it('gathers text from an associated label', () => {
    const doc = setDom(`
      <form>
        <label for="pw">Password must be 8-100 characters</label>
        <input id="pw" type="password" />
      </form>
    `);
    const input = doc.getElementById('pw') as HTMLInputElement;
    expect(collectNearbyText(input)).toContain('8-100 characters');
  });

  it('gathers text from an aria-describedby target', () => {
    const doc = setDom(`
      <form>
        <input id="pw" type="password" aria-describedby="hint" />
        <p id="hint">Must include an uppercase letter</p>
      </form>
    `);
    const input = doc.getElementById('pw') as HTMLInputElement;
    expect(collectNearbyText(input)).toContain('uppercase letter');
  });

  it('does not pull in unrelated text far outside the field\'s container', () => {
    const doc = setDom(`
      <div>
        <p>Welcome to our completely unrelated homepage content.</p>
      </div>
      <form>
        <input id="pw" type="password" />
      </form>
    `);
    const input = doc.getElementById('pw') as HTMLInputElement;
    expect(collectNearbyText(input)).not.toContain('unrelated homepage');
  });
});

describe('findPasswordFieldGroups', () => {
  it('groups a password + confirm + username set from one form', () => {
    const doc = setDom(`
      <form>
        <input id="user" type="email" />
        <input id="pw" type="password" autocomplete="new-password" />
        <input id="pw2" type="password" autocomplete="new-password" />
      </form>
    `);
    const groups = findPasswordFieldGroups(doc);
    expect(groups).toHaveLength(1);
    expect(groups[0].passwordInput.id).toBe('pw');
    expect(groups[0].confirmInput?.id).toBe('pw2');
    expect(groups[0].usernameInput?.id).toBe('user');
  });

  it('returns no groups for a plain login form', () => {
    const doc = setDom(`
      <form>
        <input id="user" type="email" />
        <input id="pw" type="password" autocomplete="current-password" />
      </form>
    `);
    expect(findPasswordFieldGroups(doc)).toHaveLength(0);
  });
});

describe('resolvePolicyForField', () => {
  it('resolves attributes and text together into a full PasswordPolicy', () => {
    const doc = setDom(`
      <form>
        <label for="pw">At least 12 characters, must include a number</label>
        <input id="pw" type="password" minlength="12" autocomplete="new-password" />
      </form>
    `);
    const input = doc.getElementById('pw') as HTMLInputElement;
    const policy = resolvePolicyForField(input, 'en');
    expect(policy.minLength).toBe(12);
    expect(policy.requireDigit).toBe(true);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run lib/formDetector.test.ts`
Expected: FAIL — `lib/formDetector.ts` does not exist yet, and the test file needs jsdom (see Step 3.5 below — until `vitest.config.ts` is updated it may also fail to find `document`).

- [ ] **Step 3: Implement `lib/formDetector.ts`**

```ts
import { parsePolicyFromAttributes, parsePolicyFromText, mergePolicies, type PasswordPolicy } from './passwordPolicy';
import type { LanguageCode } from './i18n';

export interface PasswordFieldGroup {
  passwordInput: HTMLInputElement;
  confirmInput: HTMLInputElement | null;
  usernameInput: HTMLInputElement | null;
}

const USERNAME_SELECTORS = [
  'input[autocomplete="username"]',
  'input[type="email"]',
  'input[name*="user" i]',
  'input[name*="email" i]',
];

// Bounded to English signup phrasing here — text collected via
// collectNearbyText is later parsed with the caller's configured
// rule-detection language (lib/settings.ts), but the *classification* of
// "is this a new-password field at all" stays English-only per the design
// spec's signals heuristic (an English match is a strong signal
// regardless of the page's dominant language; a miss here simply falls
// through to the other two signal types).
const SIGNUP_PHRASES = /create a password|confirm password|choose a password|set a new password|new password/i;

function ancestorsUpTo(el: Element, levels: number): Element[] {
  const result: Element[] = [];
  let current: Element | null = el;
  for (let i = 0; i < levels && current; i++) {
    current = current.parentElement;
    if (current) result.push(current);
  }
  return result;
}

export function collectNearbyText(input: HTMLInputElement): string {
  const parts: string[] = [];

  const doc = input.ownerDocument;
  if (input.id) {
    const label = doc.querySelector(`label[for="${CSS.escape(input.id)}"]`);
    if (label?.textContent) parts.push(label.textContent);
  }

  const describedBy = input.getAttribute('aria-describedby');
  if (describedBy) {
    for (const id of describedBy.split(/\s+/)) {
      const el = doc.getElementById(id);
      if (el?.textContent) parts.push(el.textContent);
    }
  }

  for (const ancestor of ancestorsUpTo(input, 3)) {
    if (['FORM', 'FIELDSET', 'DIV', 'SECTION'].includes(ancestor.tagName)) {
      parts.push(ancestor.textContent ?? '');
      break;
    }
  }

  return parts.join(' ').replace(/\s+/g, ' ').trim();
}

export function isNewPasswordContext(input: HTMLInputElement, doc: Document): boolean {
  if (input.autocomplete === 'new-password') return true;

  const container = input.closest('form, fieldset') ?? doc;
  const passwordFields = Array.from(container.querySelectorAll<HTMLInputElement>('input[type="password"]'));
  if (passwordFields.length >= 2 && passwordFields.includes(input)) return true;

  if (SIGNUP_PHRASES.test(collectNearbyText(input))) return true;

  return false;
}

export function findPasswordFieldGroups(doc: Document): PasswordFieldGroup[] {
  const groups: PasswordFieldGroup[] = [];
  const seen = new Set<HTMLInputElement>();
  const allPasswordFields = Array.from(doc.querySelectorAll<HTMLInputElement>('input[type="password"]'));

  for (const field of allPasswordFields) {
    if (seen.has(field) || !isNewPasswordContext(field, doc)) continue;

    const container = field.closest('form, fieldset') ?? doc;
    const passwordFieldsInContainer = Array.from(
      container.querySelectorAll<HTMLInputElement>('input[type="password"]'),
    ).filter((f) => !seen.has(f));

    const passwordInput = passwordFieldsInContainer[0];
    const confirmInput = passwordFieldsInContainer[1] ?? null;
    seen.add(passwordInput);
    if (confirmInput) seen.add(confirmInput);

    const usernameInput = (() => {
      for (const selector of USERNAME_SELECTORS) {
        const el = container.querySelector<HTMLInputElement>(selector);
        if (el) return el;
      }
      return null;
    })();

    groups.push({ passwordInput, confirmInput, usernameInput });
  }

  return groups;
}

export function resolvePolicyForField(input: HTMLInputElement, lang: LanguageCode): PasswordPolicy {
  const attrPolicy = parsePolicyFromAttributes({
    minLength: input.minLength >= 0 ? input.minLength : undefined,
    maxLength: input.maxLength >= 0 ? input.maxLength : undefined,
    pattern: input.pattern || undefined,
  });
  const textPolicy = parsePolicyFromText(collectNearbyText(input), lang);
  return mergePolicies(attrPolicy, textPolicy);
}
```

- [ ] **Step 4: Add `lib/formDetector.test.ts` to the jsdom Vitest project**

In `vitest.config.ts`, this test needs `document`/`HTMLInputElement` — add it alongside the other DOM-dependent `lib/*.test.ts` files already special-cased there:

```ts
        test: {
          name: 'node',
          environment: 'node',
          globals: false,
          setupFiles: ['./vitest.setup.ts'],
          include: ['**/*.{test,spec}.{ts,tsx}'],
          exclude: [
            '**/node_modules/**',
            'entrypoints/popup/**',
            'lib/fillScript.test.ts',
            'lib/matchCredentials.test.ts',
            'lib/formDetector.test.ts',
          ],
        },
```

```ts
        test: {
          name: 'jsdom',
          environment: 'jsdom',
          globals: false,
          setupFiles: ['./vitest.setup.ts'],
          include: [
            'entrypoints/popup/**/*.{test,spec}.{ts,tsx}',
            'lib/fillScript.test.ts',
            'lib/matchCredentials.test.ts',
            'lib/formDetector.test.ts',
          ],
        },
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run lib/formDetector.test.ts`
Expected: all tests PASS.

- [ ] **Step 6: Run the full suite and typecheck**

Run: `npm test && npx tsc --noEmit`
Expected: all tests pass (115 + new ones), tsc clean.

- [ ] **Step 7: Commit**

```bash
git add lib/formDetector.ts lib/formDetector.test.ts vitest.config.ts
git commit -m "feat: add lib/formDetector.ts (new-password signal detection, nearby-text collection)

Classifies whether a password field is a signup/change-password context
(vs. an ordinary login field) via three signals: autocomplete=new-password,
adjacent password+confirm fields, or nearby signup phrasing. Ties
attribute + text parsing together into resolvePolicyForField for the
content script to call per field."
```

---

### PS-Task 6: `lib/settings.ts` — auto-suggest toggle and rule-detection language storage

Two new persisted settings, independent of the existing popup UI-language storage key (`pwdnow_language`, in `lib/i18nRuntime.ts`).

**Files:**
- Create: `lib/settings.ts`
- Create: `lib/settings.test.ts`

**Interfaces:**
- Consumes: `type LanguageCode` from `@/lib/i18n`. `browser` from `wxt/browser`.
- Produces: `export function getAutoSuggestEnabled(): Promise<boolean>` (default `true`) — used by PS-Task 7 and PS-Task 9.
- Produces: `export function setAutoSuggestEnabled(enabled: boolean): Promise<void>` — used by PS-Task 7.
- Produces: `export function getRuleDetectionLanguage(): Promise<LanguageCode>` (default `'en'`) — used by PS-Task 7 and PS-Task 9.
- Produces: `export function setRuleDetectionLanguage(lang: LanguageCode): Promise<void>` — used by PS-Task 7.

- [ ] **Step 1: Write the failing tests**

Create `lib/settings.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { storageGet, storageSet } = vi.hoisted(() => ({
  storageGet: vi.fn(async () => ({})),
  storageSet: vi.fn(async () => {}),
}));
vi.mock('wxt/browser', () => ({
  browser: { storage: { local: { get: storageGet, set: storageSet } } },
}));

import {
  getAutoSuggestEnabled,
  setAutoSuggestEnabled,
  getRuleDetectionLanguage,
  setRuleDetectionLanguage,
} from './settings';

beforeEach(() => {
  storageGet.mockReset().mockResolvedValue({});
  storageSet.mockReset().mockResolvedValue(undefined);
});

describe('getAutoSuggestEnabled', () => {
  it('defaults to true when unset', async () => {
    expect(await getAutoSuggestEnabled()).toBe(true);
  });

  it('returns the stored value when set to false', async () => {
    storageGet.mockResolvedValue({ pwdnow_auto_suggest_enabled: false });
    expect(await getAutoSuggestEnabled()).toBe(false);
  });
});

describe('setAutoSuggestEnabled', () => {
  it('persists the value under the expected key', async () => {
    await setAutoSuggestEnabled(false);
    expect(storageSet).toHaveBeenCalledWith({ pwdnow_auto_suggest_enabled: false });
  });
});

describe('getRuleDetectionLanguage', () => {
  it('defaults to "en" when unset', async () => {
    expect(await getRuleDetectionLanguage()).toBe('en');
  });

  it('returns the stored language when set', async () => {
    storageGet.mockResolvedValue({ pwdnow_rule_detection_lang: 'fr' });
    expect(await getRuleDetectionLanguage()).toBe('fr');
  });
});

describe('setRuleDetectionLanguage', () => {
  it('persists the value under the expected key', async () => {
    await setRuleDetectionLanguage('de');
    expect(storageSet).toHaveBeenCalledWith({ pwdnow_rule_detection_lang: 'de' });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run lib/settings.test.ts`
Expected: FAIL — `lib/settings.ts` does not exist yet.

- [ ] **Step 3: Implement `lib/settings.ts`**

```ts
import { browser } from 'wxt/browser';
import type { LanguageCode } from './i18n';

const AUTO_SUGGEST_KEY = 'pwdnow_auto_suggest_enabled';
const RULE_LANG_KEY = 'pwdnow_rule_detection_lang';

export async function getAutoSuggestEnabled(): Promise<boolean> {
  const result = await browser.storage.local.get(AUTO_SUGGEST_KEY);
  const value = result[AUTO_SUGGEST_KEY];
  return typeof value === 'boolean' ? value : true;
}

export async function setAutoSuggestEnabled(enabled: boolean): Promise<void> {
  await browser.storage.local.set({ [AUTO_SUGGEST_KEY]: enabled });
}

export async function getRuleDetectionLanguage(): Promise<LanguageCode> {
  const result = await browser.storage.local.get(RULE_LANG_KEY);
  const value = result[RULE_LANG_KEY] as LanguageCode | undefined;
  return value ?? 'en';
}

export async function setRuleDetectionLanguage(lang: LanguageCode): Promise<void> {
  await browser.storage.local.set({ [RULE_LANG_KEY]: lang });
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/settings.test.ts`
Expected: all tests PASS.

- [ ] **Step 5: Run the full suite and typecheck**

Run: `npm test && npx tsc --noEmit`
Expected: all tests pass, tsc clean.

- [ ] **Step 6: Commit**

```bash
git add lib/settings.ts lib/settings.test.ts
git commit -m "feat: add lib/settings.ts (auto-suggest toggle, rule-detection language)

Two new storage-backed settings, independent of the existing popup
UI-language key — the options page (PS-Task 7) and content script
(PS-Task 9) both read these."
```

---

### PS-Task 7: `entrypoints/options/` — new WXT options page

A new WXT entrypoint hosting the two settings from PS-Task 6, with a language dropdown mirroring the existing `LanguageSwitcher.tsx` pattern. Opened via right-click the extension icon → Options, or `chrome://extensions` → Details → Extension options.

**Note for the implementer:** WXT's documented convention registers `entrypoints/options/index.html` as the manifest's `options_ui.page` automatically, the same way `entrypoints/popup/index.html` becomes `action.default_popup` — mirror the popup's existing file structure exactly (`index.html` + `main.tsx` + `App.tsx`). Verify this registration actually appears in `.output/chrome-mv3/manifest.json` after building (Step 6 below) before considering this task done; if the installed WXT version needs an explicit `manifest.options_ui` entry in `wxt.config.ts` instead of auto-detection, add it there (`options_ui: { page: 'options.html', open_in_tab: true }` — check the actual generated path in `.output` first).

**Files:**
- Create: `entrypoints/options/index.html`
- Create: `entrypoints/options/main.tsx`
- Create: `entrypoints/options/App.tsx`
- Create: `entrypoints/options/App.test.tsx`

**Interfaces:**
- Consumes: `initI18n` from `@/lib/i18nRuntime` (PS-Task 1). `getAutoSuggestEnabled, setAutoSuggestEnabled, getRuleDetectionLanguage, setRuleDetectionLanguage` from `@/lib/settings` (PS-Task 6). `SUPPORTED_LANGUAGES, type LanguageCode` from `@/lib/i18n`.
- No new exports consumed by later tasks — this is a leaf entrypoint.

- [ ] **Step 1: Write the failing test**

Create `entrypoints/options/App.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'vitest-axe';

const { storageGet, storageSet } = vi.hoisted(() => ({
  storageGet: vi.fn(async () => ({})),
  storageSet: vi.fn(async () => {}),
}));
vi.mock('wxt/browser', () => ({
  browser: { storage: { local: { get: storageGet, set: storageSet } } },
}));

import { initI18n } from '@/lib/i18nRuntime';
import { App } from './App';

beforeAll(async () => {
  await initI18n();
});

beforeEach(() => {
  storageGet.mockReset().mockResolvedValue({});
  storageSet.mockReset().mockResolvedValue(undefined);
});

describe('Options App', () => {
  it('shows the auto-suggest toggle defaulting to checked', async () => {
    render(<App />);
    const toggle = await screen.findByRole('checkbox', { name: /suggest passwords automatically/i });
    expect(toggle).toBeChecked();
  });

  it('toggling auto-suggest off persists the setting', async () => {
    const user = userEvent.setup();
    render(<App />);
    const toggle = await screen.findByRole('checkbox', { name: /suggest passwords automatically/i });
    await user.click(toggle);
    await waitFor(() => {
      expect(storageSet).toHaveBeenCalledWith({ pwdnow_auto_suggest_enabled: false });
    });
  });

  it('shows the rule-detection language dropdown defaulting to English', async () => {
    render(<App />);
    const select = await screen.findByLabelText(/password rule detection language/i);
    expect(select).toHaveValue('en');
  });

  it('selecting a different rule-detection language persists it', async () => {
    const user = userEvent.setup();
    render(<App />);
    const select = await screen.findByLabelText(/password rule detection language/i);
    await user.selectOptions(select, 'fr');
    await waitFor(() => {
      expect(storageSet).toHaveBeenCalledWith({ pwdnow_rule_detection_lang: 'fr' });
    });
  });

  it('has no accessibility violations', async () => {
    const { container } = render(<App />);
    await screen.findByRole('checkbox', { name: /suggest passwords automatically/i });
    expect(await axe(container)).toHaveNoViolations();
  });
});
```

Check whether `@testing-library/user-event` is already a dependency:

Run: `grep user-event package.json`

If absent, add it as a dev dependency before running the test (it is the standard companion to `@testing-library/react` for simulating real user interaction and is needed for the `selectOptions`/`click` calls above):

Run: `npm install --save-dev @testing-library/user-event`

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run entrypoints/options/App.test.tsx`
Expected: FAIL — `entrypoints/options/App.tsx` does not exist yet.

- [ ] **Step 3: Implement**

Create `entrypoints/options/index.html`:

```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>PWDnow Settings</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="./main.tsx"></script>
  </body>
</html>
```

Create `entrypoints/options/App.tsx`:

```tsx
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { SUPPORTED_LANGUAGES, type LanguageCode } from '@/lib/i18n';
import {
  getAutoSuggestEnabled,
  setAutoSuggestEnabled,
  getRuleDetectionLanguage,
  setRuleDetectionLanguage,
} from '@/lib/settings';

export function App() {
  const { t } = useTranslation();
  const [autoSuggest, setAutoSuggest] = useState(true);
  const [ruleLang, setRuleLang] = useState<LanguageCode>('en');
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    void (async () => {
      setAutoSuggest(await getAutoSuggestEnabled());
      setRuleLang(await getRuleDetectionLanguage());
      setLoaded(true);
    })();
  }, []);

  async function handleToggle() {
    const next = !autoSuggest;
    setAutoSuggest(next);
    await setAutoSuggestEnabled(next);
  }

  async function handleLangChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const next = e.target.value as LanguageCode;
    setRuleLang(next);
    await setRuleDetectionLanguage(next);
  }

  if (!loaded) {
    return (
      <main className="mx-auto max-w-md p-6">
        <p aria-live="polite">{t('common.loading')}</p>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-md p-6">
      <h1 className="mb-4 font-headline text-xl font-semibold">{t('options.title')}</h1>

      <div className="mb-4 flex items-center justify-between rounded-lg border border-outline-variant bg-surface-container-low p-4">
        <label htmlFor="auto-suggest-toggle" className="font-medium">
          {t('options.autoSuggestLabel')}
        </label>
        <input
          id="auto-suggest-toggle"
          type="checkbox"
          role="checkbox"
          checked={autoSuggest}
          onChange={handleToggle}
          className="h-5 w-5"
        />
      </div>

      <div className="rounded-lg border border-outline-variant bg-surface-container-low p-4">
        <label htmlFor="rule-lang-select" className="mb-1 block font-medium">
          {t('options.ruleLanguageLabel')}
        </label>
        <p className="mb-2 text-sm text-on-surface-variant">{t('options.ruleLanguageHint')}</p>
        <select
          id="rule-lang-select"
          value={ruleLang}
          onChange={handleLangChange}
          className="w-full rounded-lg border border-outline-variant bg-surface px-3 py-2"
        >
          {SUPPORTED_LANGUAGES.map((lang) => (
            <option key={lang.code} value={lang.code}>
              {lang.nativeName}
            </option>
          ))}
        </select>
      </div>
    </main>
  );
}
```

Create `entrypoints/options/main.tsx` (mirrors the popup's `main.tsx` init-then-render pattern — must gate on `initI18n()` exactly like the popup does, or this page will show raw translation keys just like the bug fixed in commit `4d4bc19`):

```tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import { initI18n } from '@/lib/i18nRuntime';
import '../popup/app.css';

document.documentElement.classList.toggle(
  'dark',
  window.matchMedia('(prefers-color-scheme: dark)').matches,
);

void initI18n().then(() => {
  ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
});
```

Add an `options` key to every one of the 13 locale files in `lib/locales/*.json` (English shown; translate the two label strings and the hint for the other 12 — reuse the same "uppercase/lowercase/number/special character" vocabulary already established in this same file's other sections where applicable, matching the terminology-reuse approach from the UI-overhaul plan). Add this as a new top-level key alongside `common`, `connect`, `mfa`, `vault`, `language`, `errors`:

```json
  "options": {
    "title": "PWDnow Settings",
    "autoSuggestLabel": "Suggest passwords automatically",
    "ruleLanguageLabel": "Password rule detection language",
    "ruleLanguageHint": "Which language PWDnow looks for password requirement text in on websites — independent of the language you see in the popup."
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run entrypoints/options/App.test.tsx`
Expected: all tests PASS.

- [ ] **Step 5: Run the locale-completeness test and the full suite**

Run: `npx vitest run lib/locales/locales.test.ts && npm test && npx tsc --noEmit`
Expected: locale-completeness test passes (all 13 files have the same key set including the new `options` block), full suite passes, tsc clean.

- [ ] **Step 6: Build and verify the options page is registered in the manifest**

Run: `npm run build && cat .output/chrome-mv3/manifest.json`
Expected: the build succeeds and produces an `options.html` (or equivalent) output file; the manifest JSON contains an `options_ui` (or `options_page`) entry pointing at it. If it does not appear automatically, add the explicit `options_ui` entry to `wxt.config.ts`'s `manifest` object as described in the task note above, rebuild, and re-verify.

- [ ] **Step 7: Commit**

```bash
git add entrypoints/options lib/locales wxt.config.ts package.json package-lock.json
git commit -m "feat: add extension options page (auto-suggest toggle, rule-detection language)

New WXT options entrypoint hosting the two PS-Task-6 settings. The
rule-detection language is deliberately independent of the popup's own
UI language setting (see design spec §5)."
```

---

### PS-Task 8: `entrypoints/content/Banner.tsx` — the in-page suggestion banner component

A pure, presentation-focused React component. It does not know about Shadow DOM, `MutationObserver`, or DOM field detection — the content script (PS-Task 9) mounts it and wires callbacks. This separation matches how `VaultScreen.tsx` is a plain component driven by props/callbacks rather than owning browser-extension plumbing directly (`VaultScreen.tsx` does own its own `browser.*` calls, but `Banner.tsx` is simpler and more reusable kept fully callback-driven, since PS-Task 9 needs to coordinate it with DOM mutation and Shadow DOM lifecycle).

**Files:**
- Create: `entrypoints/content/Banner.tsx`
- Create: `entrypoints/content/Banner.test.tsx`

**Interfaces:**
- Consumes: nothing new — plain React + `react-i18next` + `lucide-react`, matching existing popup component conventions.
- Produces: `export interface BannerProps { password: string; saveState: 'idle' | 'connected' | 'saving' | 'saved' | 'error'; errorMessage?: string; onUse: () => void; onRegenerate: () => void; onDismiss: () => void; onSave: () => void }` and `export function Banner(props: BannerProps): JSX.Element` — used by PS-Task 9.

**`saveState` values, exact meaning** (PS-Task 9 is the only caller and must drive this state machine correctly):
- `'idle'`: password not yet filled (or filled but not connected — nowhere to save to); only "Use this password" / "Regenerate" / dismiss are shown.
- `'connected'`: password was just filled (`onUse` was called) and the extension is connected+unlocked — show the "Save to vault?" prompt.
- `'saving'`: `onSave` was called, waiting on the background service worker's response.
- `'saved'`: save succeeded — show a confirmation.
- `'error'`: save failed after one retry — show `errorMessage` in a `role="alert"` element.

- [ ] **Step 1: Write the failing test**

Create `entrypoints/content/Banner.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeAll } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'vitest-axe';
import { initI18n } from '@/lib/i18nRuntime';
import { Banner } from './Banner';

beforeAll(async () => {
  await initI18n();
});

describe('Banner', () => {
  it('shows the suggested password and action buttons in the idle state', () => {
    render(
      <Banner
        password="Xk92!mQpLr7z"
        saveState="idle"
        onUse={vi.fn()}
        onRegenerate={vi.fn()}
        onDismiss={vi.fn()}
        onSave={vi.fn()}
      />,
    );
    expect(screen.getByText('Xk92!mQpLr7z')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /use this password/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /regenerate/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /dismiss/i })).toBeInTheDocument();
  });

  it('calls onUse when "Use this password" is clicked', async () => {
    const onUse = vi.fn();
    const user = userEvent.setup();
    render(
      <Banner password="Xk92!mQpLr7z" saveState="idle" onUse={onUse} onRegenerate={vi.fn()} onDismiss={vi.fn()} onSave={vi.fn()} />,
    );
    await user.click(screen.getByRole('button', { name: /use this password/i }));
    expect(onUse).toHaveBeenCalled();
  });

  it('calls onRegenerate when the regenerate button is clicked', async () => {
    const onRegenerate = vi.fn();
    const user = userEvent.setup();
    render(
      <Banner password="Xk92!mQpLr7z" saveState="idle" onUse={vi.fn()} onRegenerate={onRegenerate} onDismiss={vi.fn()} onSave={vi.fn()} />,
    );
    await user.click(screen.getByRole('button', { name: /regenerate/i }));
    expect(onRegenerate).toHaveBeenCalled();
  });

  it('calls onDismiss when the dismiss button is clicked', async () => {
    const onDismiss = vi.fn();
    const user = userEvent.setup();
    render(
      <Banner password="Xk92!mQpLr7z" saveState="idle" onUse={vi.fn()} onRegenerate={vi.fn()} onDismiss={onDismiss} onSave={vi.fn()} />,
    );
    await user.click(screen.getByRole('button', { name: /dismiss/i }));
    expect(onDismiss).toHaveBeenCalled();
  });

  it('shows the save prompt in the "connected" state and calls onSave', async () => {
    const onSave = vi.fn();
    const user = userEvent.setup();
    render(
      <Banner password="Xk92!mQpLr7z" saveState="connected" onUse={vi.fn()} onRegenerate={vi.fn()} onDismiss={vi.fn()} onSave={onSave} />,
    );
    await user.click(screen.getByRole('button', { name: /save to.*vault/i }));
    expect(onSave).toHaveBeenCalled();
  });

  it('shows a saved confirmation in the "saved" state', () => {
    render(
      <Banner password="Xk92!mQpLr7z" saveState="saved" onUse={vi.fn()} onRegenerate={vi.fn()} onDismiss={vi.fn()} onSave={vi.fn()} />,
    );
    expect(screen.getByText(/saved/i)).toBeInTheDocument();
  });

  it('shows an inline error message in the "error" state', () => {
    render(
      <Banner
        password="Xk92!mQpLr7z"
        saveState="error"
        errorMessage="Couldn't reach PWDnow — try the toolbar icon instead."
        onUse={vi.fn()}
        onRegenerate={vi.fn()}
        onDismiss={vi.fn()}
        onSave={vi.fn()}
      />,
    );
    expect(screen.getByRole('alert')).toHaveTextContent(/couldn't reach pwdnow/i);
  });

  it('has no accessibility violations in the idle state', async () => {
    const { container } = render(
      <Banner password="Xk92!mQpLr7z" saveState="idle" onUse={vi.fn()} onRegenerate={vi.fn()} onDismiss={vi.fn()} onSave={vi.fn()} />,
    );
    expect(await axe(container)).toHaveNoViolations();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run entrypoints/content/Banner.test.tsx`
Expected: FAIL — `entrypoints/content/Banner.tsx` does not exist yet.

- [ ] **Step 3: Implement `entrypoints/content/Banner.tsx`**

```tsx
import { useTranslation } from 'react-i18next';
import { RefreshCw, X, Check, TriangleAlert } from 'lucide-react';

export interface BannerProps {
  password: string;
  saveState: 'idle' | 'connected' | 'saving' | 'saved' | 'error';
  errorMessage?: string;
  onUse: () => void;
  onRegenerate: () => void;
  onDismiss: () => void;
  onSave: () => void;
}

export function Banner({ password, saveState, errorMessage, onUse, onRegenerate, onDismiss, onSave }: BannerProps) {
  const { t } = useTranslation();

  return (
    <div className="w-80 rounded-xl border border-outline-variant bg-surface-container-low p-3 shadow-lg">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="font-headline text-sm font-semibold">{t('banner.suggestionTitle')}</h2>
        <button type="button" aria-label={t('banner.dismiss')} onClick={onDismiss} className="text-on-surface-variant">
          <X aria-hidden="true" focusable="false" size={16} />
        </button>
      </div>

      <p className="mb-2 rounded-lg bg-surface-container-high p-2 text-center font-mono text-sm">{password}</p>

      {saveState === 'idle' && (
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onUse}
            className="flex-1 rounded-lg bg-primary-container px-3 py-2 text-sm font-medium text-on-primary-container"
          >
            {t('banner.useButton')}
          </button>
          <button
            type="button"
            aria-label={t('banner.regenerate')}
            onClick={onRegenerate}
            className="rounded-lg border border-outline-variant px-2"
          >
            <RefreshCw aria-hidden="true" focusable="false" size={16} />
          </button>
        </div>
      )}

      {saveState === 'connected' && (
        <div>
          <p className="mb-2 text-sm">{t('banner.savePrompt')}</p>
          <button
            type="button"
            onClick={onSave}
            className="w-full rounded-lg bg-primary-container px-3 py-2 text-sm font-medium text-on-primary-container"
          >
            {t('banner.saveButton')}
          </button>
        </div>
      )}

      {saveState === 'saving' && <p aria-live="polite" className="text-sm">{t('banner.saving')}</p>}

      {saveState === 'saved' && (
        <p aria-live="polite" className="flex items-center gap-1 text-sm text-on-surface-variant">
          <Check aria-hidden="true" focusable="false" size={16} />
          {t('banner.saved')}
        </p>
      )}

      {saveState === 'error' && (
        <p role="alert" className="flex items-center gap-1 text-sm text-error">
          <TriangleAlert aria-hidden="true" focusable="false" size={16} />
          {errorMessage}
        </p>
      )}
    </div>
  );
}
```

Add a `banner` key to every one of the 13 locale files in `lib/locales/*.json` (English shown; translate for the other 12, reusing existing vocabulary — "use"/"save"/"saved" concepts already exist in the `vault` section of these same files and should reuse identical wording where the meaning matches, per the same terminology-consistency approach used throughout this project):

```json
  "banner": {
    "suggestionTitle": "Suggested password",
    "useButton": "Use this password",
    "regenerate": "Regenerate",
    "dismiss": "Dismiss",
    "savePrompt": "Save this to your PWDnow vault?",
    "saveButton": "Save to vault",
    "saving": "Saving…",
    "saved": "Saved to your vault"
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run entrypoints/content/Banner.test.tsx`
Expected: all tests PASS.

- [ ] **Step 5: Run the locale-completeness test and full suite**

Run: `npx vitest run lib/locales/locales.test.ts && npm test && npx tsc --noEmit`
Expected: all pass, tsc clean. (`entrypoints/content/**` will need adding to `vitest.config.ts`'s jsdom project for this to even be discovered — see PS-Task 9 Step 6, which does this alongside the content-script test; if `Banner.test.tsx` is not yet picked up by either project, add the config change now instead of waiting for PS-Task 9.)

- [ ] **Step 6: Commit**

```bash
git add entrypoints/content/Banner.tsx entrypoints/content/Banner.test.tsx lib/locales vitest.config.ts
git commit -m "feat: add Banner.tsx, the in-page password suggestion UI

Pure, callback-driven component (idle/connected/saving/saved/error
states) — no Shadow DOM or DOM-detection logic here, that's PS-Task 9's
content script, which mounts and drives this component."
```

---

### PS-Task 9: `entrypoints/content/index.tsx` — the persistent content script

Wires everything together: manifest permission changes, initial scan + `MutationObserver`, Shadow DOM mounting, and the fill/save message flow.

**Files:**
- Create: `entrypoints/content/index.tsx`
- Create: `entrypoints/content/index.test.ts`
- Modify: `wxt.config.ts` (add `host_permissions: ['<all_urls>']`)
- Modify: `vitest.config.ts` (add `entrypoints/content/**` to the jsdom project, exclude from node — same pattern as PS-Task 5's `formDetector.test.ts`; if PS-Task 8 already made this change, skip)
- Modify: `lib/fillScript.ts` (export `setNativeValue`, currently private — the content script reuses it directly since it already runs in-page, unlike the popup's fill flow which needs `browser.scripting.executeScript` to reach a *different* tab)
- Modify: `lib/messages.ts` (no new message types needed — `getStatus` and `saveCredential` already exist and are reused as-is)

**Interfaces:**
- Consumes: `findPasswordFieldGroups, resolvePolicyForField, type PasswordFieldGroup` from `@/lib/formDetector` (PS-Task 5). `generateCompliantPassword` from `@/lib/passwordPolicy` (PS-Task 3). `getAutoSuggestEnabled, getRuleDetectionLanguage` from `@/lib/settings` (PS-Task 6). `initI18n` from `@/lib/i18nRuntime` (PS-Task 1). `Banner, type BannerProps` from `./Banner` (PS-Task 8). `setNativeValue` from `@/lib/fillScript` (modified this task). `type ExtMessage, type ExtResponse` from `@/lib/messages` (existing). `browser` from `wxt/browser`.
- Produces: `export function scanAndMount(doc: Document, deps: ScanDeps): void` (the orchestration function, exported specifically so it's unit-testable without a real Shadow DOM — see the test below; the mount point per field group comes from `deps.resolveMountPoint`, not a separate parameter) and the `default defineContentScript(...)` entrypoint itself.

- [ ] **Step 1: Export `setNativeValue` from `lib/fillScript.ts`**

In `lib/fillScript.ts`, change:
```ts
function setNativeValue(el: HTMLInputElement, value: string): void {
```
to:
```ts
export function setNativeValue(el: HTMLInputElement, value: string): void {
```

(Purely additive — no existing test or behavior changes. Run `npx vitest run lib/fillScript.test.ts` afterward to confirm the existing tests still pass unchanged.)

- [ ] **Step 2: Write the failing test for the orchestration logic**

Create `entrypoints/content/index.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { sendMessage, storageGet } = vi.hoisted(() => ({
  sendMessage: vi.fn(),
  storageGet: vi.fn(async () => ({})),
}));
vi.mock('wxt/browser', () => ({
  browser: { runtime: { sendMessage }, storage: { local: { get: storageGet } } },
}));

import { scanAndMount, type ScanDeps } from './index';

function setDom(html: string): Document {
  document.body.innerHTML = html;
  return document;
}

function fakeShadowRoot(): { root: ShadowRoot; host: HTMLElement } {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = host.attachShadow({ mode: 'open' });
  return { root, host };
}

describe('scanAndMount', () => {
  beforeEach(() => {
    sendMessage.mockReset();
    storageGet.mockReset().mockResolvedValue({});
  });

  it('mounts a banner for a qualifying signup-form fixture', () => {
    const doc = setDom(`
      <form>
        <input id="email" type="email" />
        <input id="pw" type="password" autocomplete="new-password" />
      </form>
    `);
    const { root } = fakeShadowRoot();
    const deps: ScanDeps = {
      resolveMountPoint: () => root,
      ruleLanguage: 'en',
      autoSuggestEnabled: true,
    };
    scanAndMount(doc, deps);
    expect(root.childElementCount).toBeGreaterThan(0);
    expect(root.querySelector('link[data-pwdnow-styles]')).not.toBeNull();
  });

  it('does not mount a banner for an ordinary login-form fixture', () => {
    const doc = setDom(`
      <form>
        <input id="email" type="email" />
        <input id="pw" type="password" autocomplete="current-password" />
      </form>
    `);
    const { root } = fakeShadowRoot();
    const deps: ScanDeps = {
      resolveMountPoint: () => root,
      ruleLanguage: 'en',
      autoSuggestEnabled: true,
    };
    scanAndMount(doc, deps);
    expect(root.childElementCount).toBe(0);
  });

  it('does not mount anything when auto-suggest is disabled', () => {
    const doc = setDom(`<form><input id="pw" type="password" autocomplete="new-password" /></form>`);
    const { root } = fakeShadowRoot();
    const deps: ScanDeps = {
      resolveMountPoint: () => root,
      ruleLanguage: 'en',
      autoSuggestEnabled: false,
    };
    scanAndMount(doc, deps);
    expect(root.childElementCount).toBe(0);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run entrypoints/content/index.test.ts`
Expected: FAIL — `entrypoints/content/index.tsx` does not exist yet.

- [ ] **Step 4: Implement `entrypoints/content/index.tsx`**

```tsx
import { createRoot, type Root } from 'react-dom/client';
import { browser } from 'wxt/browser';
import { findPasswordFieldGroups, resolvePolicyForField, type PasswordFieldGroup } from '@/lib/formDetector';
import { generateCompliantPassword } from '@/lib/passwordPolicy';
import { getAutoSuggestEnabled, getRuleDetectionLanguage } from '@/lib/settings';
import { initI18n } from '@/lib/i18nRuntime';
import { setNativeValue } from '@/lib/fillScript';
import type { ExtMessage, ExtResponse } from '@/lib/messages';
import type { LanguageCode } from '@/lib/i18n';
import { Banner, type BannerProps } from './Banner';
// Vite's `?url` suffix resolves to the built asset's runtime URL string
// instead of inlining/parsing the file as CSS — a standard Vite feature
// (not WXT-specific), used here because this stylesheet must be injected
// manually into the Shadow DOM root (see mountBanner below) rather than
// loaded normally via a document-head <link>. Verify after Step 8's build
// that this resolves to a real, loadable asset path inside
// `.output/chrome-mv3/` — if the installed WXT/Vite version handles
// content-script CSS assets differently, adjust this import accordingly,
// but the shadow-root injection logic below must still end up pointing at
// *some* real URL for the compiled app.css.
import bannerStylesUrl from '../popup/app.css?url';

export interface ScanDeps {
  resolveMountPoint: (group: PasswordFieldGroup) => ShadowRoot | null;
  ruleLanguage: LanguageCode;
  autoSuggestEnabled: boolean;
}

const dismissed = new WeakSet<HTMLInputElement>();
const mountedRoots = new Map<HTMLInputElement, Root>();

function mountBanner(container: ShadowRoot, group: PasswordFieldGroup, ruleLanguage: LanguageCode): void {
  // Shadow DOM style encapsulation cuts both ways: the host page's CSS
  // can't leak in, but the extension's own compiled Tailwind CSS (already
  // loaded by the popup/options page via a normal <link>/<style> in their
  // own document head) does NOT cross the shadow boundary either — it
  // must be attached to *this* shadow root explicitly, once per host
  // element, or the Banner renders completely unstyled.
  if (!container.querySelector('link[data-pwdnow-styles]')) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = bannerStylesUrl;
    link.dataset.pwdnowStyles = 'true';
    container.appendChild(link);
  }

  const mountEl = document.createElement('div');
  container.appendChild(mountEl);
  const reactRoot = createRoot(mountEl);
  mountedRoots.set(group.passwordInput, reactRoot);

  let password = generateCompliantPassword(resolvePolicyForField(group.passwordInput, ruleLanguage));
  let saveState: BannerProps['saveState'] = 'idle';
  let errorMessage: string | undefined;

  function renderBanner(): void {
    // Must go through JSX (React.createElement under the hood), not a
    // plain `Banner({...})` function call — Banner uses `useTranslation()`
    // internally, which requires React's dispatcher context. Calling the
    // component function directly bypasses that and throws "Invalid hook
    // call." This is also why this file is `.tsx`, not `.ts`.
    reactRoot.render(
      <Banner
        password={password}
        saveState={saveState}
        errorMessage={errorMessage}
        onUse={handleUse}
        onRegenerate={handleRegenerate}
        onDismiss={handleDismiss}
        onSave={handleSave}
      />,
    );
  }

  function handleUse(): void {
    setNativeValue(group.passwordInput, password);
    if (group.confirmInput) setNativeValue(group.confirmInput, password);
    if (group.usernameInput?.value) {
      // Username is left untouched — nothing to fill there beyond what the
      // user already entered; PWDnow only fills passwords in this flow.
    }
    void checkConnectionAndOffer();
  }

  async function checkConnectionAndOffer(): Promise<void> {
    try {
      const message: ExtMessage = { type: 'getStatus' };
      const response = (await browser.runtime.sendMessage(message)) as ExtResponse;
      if (response.type === 'status' && response.connected && response.unlocked) {
        saveState = 'connected';
      } else {
        saveState = 'idle';
      }
    } catch {
      saveState = 'idle';
    }
    renderBanner();
  }

  function handleRegenerate(): void {
    password = generateCompliantPassword(resolvePolicyForField(group.passwordInput, ruleLanguage));
    renderBanner();
  }

  function handleDismiss(): void {
    dismissed.add(group.passwordInput);
    reactRoot.unmount();
    mountedRoots.delete(group.passwordInput);
  }

  async function handleSave(attempt = 0): Promise<void> {
    saveState = 'saving';
    renderBanner();
    try {
      const message: ExtMessage = {
        type: 'saveCredential',
        credential: {
          service: location.hostname,
          url: `https://${location.hostname}`,
          username: group.usernameInput?.value ?? '',
          password,
        },
      };
      const response = (await browser.runtime.sendMessage(message)) as ExtResponse;
      if (response.type === 'saveResult' && response.ok) {
        saveState = 'saved';
      } else if (attempt < 1) {
        await handleSave(attempt + 1);
        return;
      } else {
        saveState = 'error';
        errorMessage = "Couldn't reach PWDnow — try the toolbar icon instead.";
      }
    } catch {
      if (attempt < 1) {
        await handleSave(attempt + 1);
        return;
      }
      saveState = 'error';
      errorMessage = "Couldn't reach PWDnow — try the toolbar icon instead.";
    }
    renderBanner();
  }

  renderBanner();
}

export function scanAndMount(doc: Document, deps: ScanDeps): void {
  if (!deps.autoSuggestEnabled) return;

  const groups = findPasswordFieldGroups(doc);
  for (const group of groups) {
    if (dismissed.has(group.passwordInput)) continue;
    if (mountedRoots.has(group.passwordInput)) continue;
    const mountPoint = deps.resolveMountPoint(group);
    if (!mountPoint) continue;
    try {
      mountBanner(mountPoint, group, deps.ruleLanguage);
    } catch {
      // Never let a mount failure throw into the host page's own script
      // execution context.
    }
  }
}

export default defineContentScript({
  matches: ['<all_urls>'],
  runAt: 'document_idle',
  async main() {
    await initI18n();
    const [autoSuggestEnabled, ruleLanguage] = await Promise.all([
      getAutoSuggestEnabled(),
      getRuleDetectionLanguage(),
    ]);
    if (!autoSuggestEnabled) return;

    const host = document.createElement('div');
    host.style.all = 'initial';
    document.body.appendChild(host);
    const shadowRoot = host.attachShadow({ mode: 'closed' });

    const deps = { resolveMountPoint: () => shadowRoot, ruleLanguage, autoSuggestEnabled };
    scanAndMount(document, deps);

    const observer = new MutationObserver(() => {
      scanAndMount(document, deps);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  },
});
```

- [ ] **Step 5: Add `host_permissions` to `wxt.config.ts`**

In `wxt.config.ts`, change:
```ts
    permissions: ['storage', 'scripting', 'activeTab'],
    optional_host_permissions: ['*://*/*'],
```
to:
```ts
    permissions: ['storage', 'scripting', 'activeTab'],
    // Required (not optional) because the password-policy-scanner content
    // script (entrypoints/content/index.tsx) must run on every page you
    // visit to detect new-password fields automatically — a materially
    // bigger permission ask than v1's one-time, origin-scoped optional
    // grant below, and a deliberate, spec-approved trade-off.
    host_permissions: ['<all_urls>'],
    optional_host_permissions: ['*://*/*'],
```

- [ ] **Step 6: Add `entrypoints/content/**` to the jsdom Vitest project**

In `vitest.config.ts`'s node project `exclude` array, add `'entrypoints/content/**'` alongside `'entrypoints/popup/**'`. In the jsdom project's `include` array, add `'entrypoints/content/**/*.{test,spec}.{ts,tsx}'` alongside the existing `'entrypoints/popup/**/*.{test,spec}.{ts,tsx}'` entry. (If PS-Task 8 already made this exact change, this step is a no-op — verify with `git diff vitest.config.ts` before editing again.)

- [ ] **Step 7: Run tests to verify they pass**

Run: `npx vitest run entrypoints/content/index.test.ts`
Expected: all 3 tests PASS.

- [ ] **Step 8: Run the full suite, typecheck, and both production builds**

Run: `npm test && npx tsc --noEmit && npm run build && npm run build:firefox`
Expected: all tests pass, tsc clean, both builds succeed. Then verify the new permission and content script registration landed:

Run: `cat .output/chrome-mv3/manifest.json`
Expected: `host_permissions` includes `<all_urls>`, and a `content_scripts` array entry references the compiled content script bundle.

- [ ] **Step 9: Commit**

```bash
git add entrypoints/content/index.tsx entrypoints/content/index.test.ts wxt.config.ts vitest.config.ts lib/fillScript.ts
git commit -m "feat: add the persistent content script (scan, MutationObserver, banner mounting)

Wires PS-Tasks 1/3/5/6/8 together: initial scan + MutationObserver using
findPasswordFieldGroups, resolvePolicyForField + generateCompliantPassword
per qualifying field, mounted into a closed-mode Shadow DOM via Banner.
Fill reuses lib/fillScript.ts's setNativeValue directly (now exported)
since the content script already runs in-page. Save retries once on
failure before showing an inline error state. Adds the required
host_permissions: ['<all_urls>'] permission this capability depends on."
```

---

### PS-Task 10: Manual E2E checklist additions and final whole-branch review

Mirrors the closing task of both prior plans in this repo (`docs/superpowers/plans/2026-07-21-browser-extension.md`'s final task and `2026-07-21-extension-ui-i18n-a11y.md`'s UI-Task 9).

**Files:**
- Modify: `docs/MANUAL_E2E_CHECKLIST.md`

**Interfaces:** none — this task produces no code, only documentation plus the final review.

- [ ] **Step 1: Add new checklist items**

Append to `docs/MANUAL_E2E_CHECKLIST.md`:

```markdown
16. **Password suggestion banner (signup form)** — visit a page with a fixture signup form (password + confirm-password fields, or `autocomplete="new-password"`). Confirm a banner appears automatically near the field showing a generated password.
17. **Password suggestion — login form (negative case)** — visit a page with an ordinary login form (single password field, `autocomplete="current-password"`). Confirm NO banner appears.
18. **Use this password** — click "Use this password" in the banner; confirm the password field (and confirm field, if present) is filled, and — if connected+unlocked — a "Save to vault?" prompt appears.
19. **Regenerate** — click the regenerate icon; confirm the displayed password changes.
20. **Dismiss** — click the dismiss (×) button; confirm the banner disappears for that field, and does not reappear on the same page without a reload.
21. **Options page settings** — open the extension's Options page (right-click the toolbar icon → Options). Toggle "Suggest passwords automatically" off, reload a signup-form fixture page, confirm no banner appears. Turn it back on. Change "Password rule detection language" to French, confirm it persists across reopening the Options page.
22. **SPA-rendered password field** — on a page where a password field is added to the DOM after initial load (e.g. via a JS-driven "Sign up" tab switch), confirm the banner still appears without a page reload (verifies the `MutationObserver`).
```

- [ ] **Step 2: Verify the whole suite one more time and generate the final review package**

Run:
```bash
cd /home/pwd-vm/Documents/PWDnow_extension
npm test && npx tsc --noEmit && npm run build && npm run build:firefox
git log --oneline e90ee95..HEAD
git diff e90ee95..HEAD > .superpowers/sdd/ps-final-review-package.diff
```
Expected: all green; the diff file is created (base `e90ee95` is the commit at the start of the UI/i18n/a11y plan's final review — using it as the base here means the review package covers this entire new plan's commits on top of an already-fully-reviewed baseline).

- [ ] **Step 3: Commit the checklist update**

```bash
git add docs/MANUAL_E2E_CHECKLIST.md
git commit -m "docs: add manual E2E checklist items for the password policy scanner"
```

- [ ] **Step 4: Dispatch the final whole-branch review**

Following the exact pattern used for both prior plans in this repo: dispatch a fresh review (opus-tier judgment recommended, matching the two prior final reviews) covering, at minimum:
- Cross-task integration: does `entrypoints/content/index.tsx`'s real `defineContentScript` `main()` actually call `initI18n()` before any translated text renders (the exact regression class caught in the prior plan's final review) — verify by reading the file, not by trusting the plan.
- Does the options page (`entrypoints/options/main.tsx`) also gate render on `initI18n()`?
- Real command output confirming `host_permissions: ["<all_urls>"]` and the content script registration actually appear in a freshly-built `.output/*/manifest.json` for both Chrome and Firefox targets.
- Whether `generateCompliantPassword`'s length-clamping and required-class-dropping logic (PS-Task 3) could ever produce a password that violates a *stricter-than-fallback* site policy in a way that would get rejected by that site (i.e., re-verify the property-based tests actually exercise realistic contradictory policies, not just the ones in the plan).
- Whether the 12 non-English text-pattern sets (PS-Task 4) are linguistically sound — ideally spot-checked by independently translating a couple of the test fixture sentences back to English and confirming they say what the plan claims.
- Whether `isNewPasswordContext`'s signals heuristic has any realistic false-positive/false-negative gap beyond the plan's own fixtures (e.g. a password-change form with only one password field and no recognizable signup phrasing — does the plan's own scope in the design spec already accept this as an acceptable miss, or does it need a fourth signal?).
- General correctness pass over the full diff for anything else — broken imports, leftover debug statements, a11y regressions in the new options page / banner.

Findings triaged and fixed with the same Critical/Important/Minor rigor as both prior final reviews in this repo, and the ledger at `.superpowers/sdd/progress.md` updated accordingly with a final "Ready to merge: Yes/No" verdict.
