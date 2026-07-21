# Browser Extension (Chrome/Edge/Firefox) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working Chrome/Edge/Firefox extension at `~/Documents/PWDnow_extension` (a separate git repo, NOT inside `PWDnow/`) that logs into a PWDnow server-mode instance, lists credentials matching the active tab's domain, fills them into the page, generates new passwords, and saves new credentials back to the vault.

**Architecture:** WXT (Manifest V3, TypeScript, React popup) with a background service worker that owns all server communication. Every HTTP call to the PWDnow server is executed via `chrome.scripting.executeScript` inside a dedicated, pinned, invisible tab of the configured PWDnow origin — genuinely same-origin, so cookies/CSRF work with zero server-side changes. The extension independently re-derives the same PBKDF2-SHA-512 v1 key the web app uses for server-mode vault blobs, from a master password entered in the popup; the derived key (never the password) is cached in `chrome.storage.session`.

**Tech Stack:** WXT, React 19, TypeScript, Vitest (+ jsdom for DOM-touching modules), `wxt/browser` (webextension-polyfill-backed, promise-based, cross-browser).

## Global Constraints

- Extension code lives entirely under `~/Documents/PWDnow_extension` — never under `~/PWDnow`.
- Master password is never written to any storage (local/session/disk) — used only transiently in memory during key derivation.
- The derived AES-GCM key is cached only in `chrome.storage.session` (cleared on browser close), exported/imported as raw bytes.
- Server-mode vault crypto must match `PWDnow/web/src/crypto/keystore.ts`'s v1 path exactly: `PBKDF2-SHA-512(password, saltBytes, 600_000 iterations)` → 64 bytes → first 32 bytes = AES-256-GCM key. Blob format: `BASE64URL(12-byte IV ‖ AES-GCM ciphertext+tag)`, matching `web/src/utils/localCrypto.ts`'s `encryptForServer`/`decryptFromServer`.
- All HTTP calls to the configured PWDnow origin go through the relay-tab mechanism (`lib/relay.ts`) — never a direct `fetch` from the background worker's own context.
- Host permission for the PWDnow origin is requested narrowly at connect time (`browser.permissions.request({origins:[origin + '/*']})`), never broadly granted upfront.
- Use `browser` from `wxt/browser` for all extension APIs (tabs, scripting, storage, runtime, permissions) — not the raw `chrome.*` namespace — so behavior is identical on Chrome, Edge, and Firefox.
- TypeScript strict mode. No dependencies beyond what's listed in Task 1 (YAGNI).
- Reference spec: `PWDnow/docs/superpowers/specs/2026-07-21-browser-extension-design.md`.

---

### Task 1: Repo & toolchain scaffold

**Files:**
- Create: `package.json`, `tsconfig.json`, `wxt.config.ts`, `vitest.config.ts`, `.gitignore`
- Create: `entrypoints/background.ts`, `entrypoints/popup/index.html`, `entrypoints/popup/main.tsx`, `entrypoints/popup/App.tsx`
- Test: `entrypoints/popup/App.test.tsx`

**Interfaces:**
- Produces: the `@/` path alias (project root), the `wxt/browser` API surface used by every later task, a working `npm test` and `npm run build` pipeline.

- [ ] **Step 1: Initialize the repo**

```bash
mkdir -p ~/Documents/PWDnow_extension
cd ~/Documents/PWDnow_extension
git init
```

- [ ] **Step 2: Write `package.json`**

```json
{
  "name": "pwdnow-extension",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "wxt",
    "dev:firefox": "wxt -b firefox",
    "build": "wxt build",
    "build:firefox": "wxt build -b firefox",
    "zip": "wxt zip",
    "zip:firefox": "wxt zip -b firefox",
    "compile": "tsc --noEmit",
    "test": "vitest run",
    "postinstall": "wxt prepare"
  },
  "dependencies": {
    "react": "^19.0.0",
    "react-dom": "^19.0.0"
  },
  "devDependencies": {
    "wxt": "^0.19.0",
    "@wxt-dev/module-react": "^1.0.0",
    "@testing-library/react": "^16.0.0",
    "@testing-library/jest-dom": "^6.4.0",
    "typescript": "^5.6.0",
    "vitest": "^2.1.0",
    "jsdom": "^25.0.0",
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0"
  }
}
```

- [ ] **Step 3: Install dependencies**

```bash
npm install
```

Expected: installs cleanly and `wxt prepare` (via `postinstall`) generates a `.wxt/` directory with a base `tsconfig.json` to extend. If `wxt prepare` fails because `wxt.config.ts` doesn't exist yet, that's expected at this point — proceed to Step 4 and re-run `npx wxt prepare` at the end of Step 8.

- [ ] **Step 4: Write `wxt.config.ts`**

```typescript
import { defineConfig } from 'wxt';
import path from 'node:path';

export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  alias: {
    '@': path.resolve(__dirname, '.'),
  },
  manifest: {
    name: 'PWDnow',
    description: 'Autofill and save passwords from your PWDnow vault.',
    permissions: ['storage', 'scripting', 'activeTab'],
    optional_host_permissions: ['*://*/*'],
  },
});
```

- [ ] **Step 5: Write `tsconfig.json`**

```json
{
  "extends": "./.wxt/tsconfig.json",
  "compilerOptions": {
    "paths": {
      "@/*": ["./*"]
    }
  }
}
```

- [ ] **Step 6: Write `vitest.config.ts`**

```typescript
import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },
  test: {
    environment: 'node',
    environmentMatchGlobs: [
      ['entrypoints/popup/**', 'jsdom'],
      ['lib/fillScript.test.ts', 'jsdom'],
      ['lib/matchCredentials.test.ts', 'jsdom'],
    ],
    globals: false,
    setupFiles: ['./vitest.setup.ts'],
  },
});
```

- [ ] **Step 7: Write `vitest.setup.ts`**

```typescript
import '@testing-library/jest-dom/vitest';
```

- [ ] **Step 8: Write `.gitignore`**

```
node_modules/
.wxt/
.output/
dist/
*.log
```

- [ ] **Step 9: Write background/popup entrypoints**

`entrypoints/background.ts`:

```typescript
export default defineBackground(() => {
  console.log('PWDnow extension background started');
});
```

`entrypoints/popup/index.html`:

```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>PWDnow</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="./main.tsx"></script>
  </body>
</html>
```

`entrypoints/popup/main.tsx`:

```tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
```

`entrypoints/popup/App.tsx` (stub — replaced in Tasks 11–12):

```tsx
export default function App() {
  return <h1>PWDnow</h1>;
}
```

- [ ] **Step 10: Write the smoke test**

`entrypoints/popup/App.test.tsx`:

```tsx
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import App from './App';

describe('App', () => {
  it('renders the PWDnow heading', () => {
    render(<App />);
    expect(screen.getByText('PWDnow')).toBeInTheDocument();
  });
});
```

- [ ] **Step 11: Run tests**

Run: `npm test`
Expected: 1 test file, 1 test, PASS.

- [ ] **Step 12: Verify the build**

Run: `npx wxt prepare && npm run build`
Expected: succeeds, produces `.output/chrome-mv3/manifest.json` with `permissions: ["storage","scripting","activeTab"]` and `optional_host_permissions: ["*://*/*"]`.

If any WXT config key name in this task doesn't match the installed WXT version's actual API (this is a fast-moving toolchain), fix the mechanical mismatch here — this task exists specifically to catch that before 11 more tasks build on top of it.

- [ ] **Step 13: Commit**

```bash
git add -A
git commit -m "chore: scaffold WXT extension project"
```

---

### Task 2: Server-mode crypto (KDF + blob encrypt/decrypt)

**Files:**
- Create: `lib/crypto.ts`
- Test: `lib/crypto.test.ts`

**Interfaces:**
- Produces: `deriveServerKey(password: string, saltHex: string): Promise<CryptoKey>`, `encryptForServer(key: CryptoKey, value: string): Promise<string>`, `decryptFromServer(key: CryptoKey, token: string): Promise<string | null>` — consumed by `lib/session.ts` (Task 7).

This ports `PWDnow/web/src/crypto/keystore.ts`'s v1 derivation and `PWDnow/web/src/utils/localCrypto.ts`'s `encryptForServer`/`decryptFromServer` exactly (verified against the real source). The test vector below was computed directly with Node's WebCrypto using the identical algorithm, so it cross-checks real interop, not just internal self-consistency.

- [ ] **Step 1: Write the failing tests**

`lib/crypto.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { deriveServerKey, encryptForServer, decryptFromServer } from './crypto';

describe('deriveServerKey', () => {
  it('matches the known PBKDF2-SHA-512 vector from PWDnow web (600,000 iterations)', async () => {
    const key = await deriveServerKey('correct horse battery staple', 'aabbccddeeff00112233445566778899');
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    const hex = Array.from(raw).map((b) => b.toString(16).padStart(2, '0')).join('');
    expect(hex).toBe('1b31ddb19ed370caaccc0b8dbc26dd8b478182a5580b07d4548ef7dcb22e8f53');
  });

  it('rejects a non-hex salt', async () => {
    await expect(deriveServerKey('pw', 'not-a-hex-salt')).rejects.toThrow();
  });
});

describe('encryptForServer / decryptFromServer', () => {
  it('round-trips a plaintext value', async () => {
    const key = await deriveServerKey('correct horse battery staple', 'aabbccddeeff00112233445566778899');
    const token = await encryptForServer(key, '{"hello":"world"}');
    const decrypted = await decryptFromServer(key, token);
    expect(decrypted).toBe('{"hello":"world"}');
  });

  it('returns null for a corrupted token', async () => {
    const key = await deriveServerKey('correct horse battery staple', 'aabbccddeeff00112233445566778899');
    const decrypted = await decryptFromServer(key, 'not-a-valid-token');
    expect(decrypted).toBeNull();
  });

  it('returns null when decrypting with the wrong key', async () => {
    const key1 = await deriveServerKey('password-one', 'aabbccddeeff00112233445566778899');
    const key2 = await deriveServerKey('password-two', 'aabbccddeeff00112233445566778899');
    const token = await encryptForServer(key1, 'secret');
    const decrypted = await decryptFromServer(key2, token);
    expect(decrypted).toBeNull();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run lib/crypto.test.ts`
Expected: FAIL with "Cannot find module './crypto'".

- [ ] **Step 3: Write the implementation**

`lib/crypto.ts`:

```typescript
// Ports PWDnow/web/src/crypto/keystore.ts's v1 derivation (PBKDF2-SHA-512,
// 600,000 iterations) and web/src/utils/localCrypto.ts's encryptForServer/
// decryptFromServer blob format exactly, so extension-encrypted server blobs
// are interchangeable with the web app's.
const PBKDF2_V1_ITERS = 600_000;

function hexToBytes(hex: string): Uint8Array {
  const pairs = hex.match(/../g);
  if (!pairs) throw new Error('hexToBytes: invalid hex string');
  return Uint8Array.from(pairs.map((h) => parseInt(h, 16)));
}

function toB64u(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64u(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/**
 * Derives the same AES-256-GCM key PWDnow's web app uses to encrypt
 * server-stored vault blobs. `saltHex` must be the 32-char hex `cryptoSalt`
 * delivered via the `X-Vault-Salt` response header.
 */
export async function deriveServerKey(password: string, saltHex: string): Promise<CryptoKey> {
  if (!/^[0-9a-f]{32}$/i.test(saltHex)) {
    throw new Error(`deriveServerKey: expected a 32-char hex salt, got: ${saltHex}`);
  }
  const saltBytes = hexToBytes(saltHex);
  const passwordBytes = new TextEncoder().encode(password);
  const base = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
  const raw = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-512', salt: saltBytes, iterations: PBKDF2_V1_ITERS },
      base,
      512,
    ),
  );
  const aesKeyBytes = raw.slice(0, 32);
  const key = await crypto.subtle.importKey('raw', aesKeyBytes, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  raw.fill(0);
  return key;
}

/** Matches web/src/utils/localCrypto.ts encryptForServer's blob format exactly. */
export async function encryptForServer(key: CryptoKey, value: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(value)),
  );
  const payload = new Uint8Array(iv.length + ct.length);
  payload.set(iv);
  payload.set(ct, iv.length);
  return toB64u(payload);
}

export async function decryptFromServer(key: CryptoKey, token: string): Promise<string | null> {
  try {
    const ivCt = fromB64u(token);
    const iv = ivCt.slice(0, 12);
    const ct = ivCt.slice(12);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/crypto.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/crypto.ts lib/crypto.test.ts
git commit -m "feat: port server-mode PBKDF2 key derivation and blob crypto"
```

---

### Task 3: Diceware word list (for passphrase generation)

**Files:**
- Create: `lib/wordlist.ts`, `docs/WORDLIST_SOURCE.md`
- Test: `lib/wordlist.test.ts`

**Interfaces:**
- Produces: `export const WORDLIST: readonly string[]` (exactly 7776 unique lowercase entries) — consumed by `lib/passwordGenerator.ts` (Task 4).

This task fetches the canonical EFF large wordlist (the standard, widely-mirrored 7776-word diceware list: `https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt`) rather than hand-authoring word data. **If the fetch fails, or the content doesn't validate per Step 3, stop and report to the user instead of substituting partial or fabricated word data** — do not guess at word list contents.

- [ ] **Step 1: Fetch the word list**

Use the WebFetch tool: URL `https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt`, prompt: "Return the complete raw text content of this file unmodified, with no summarization." Save the raw response to a temporary file for parsing.

- [ ] **Step 2: Parse into a word array**

Each non-empty line has the format `<5-digit-dice-roll>\t<word>` (e.g. `11111\tabacus`). Extract only the word column, in file order, into a JS array.

- [ ] **Step 3: Validate before writing anything**

Verify all of:
- Exactly 7776 entries.
- No duplicates (`new Set(words).size === 7776`).
- Every entry matches `/^[a-z]+(-[a-z]+)*$/` (lowercase ASCII words, optionally hyphenated compounds like `drop-down` — the real EFF list contains a handful of these — no whitespace/tabs leaked in).

If any check fails, STOP this task and report the discrepancy rather than writing a partial/corrupted list.

- [ ] **Step 4: Write `lib/wordlist.ts`**

```typescript
// Source: EFF large wordlist (7776 words, 5-dice diceware), fetched
// 2026-07-21 from https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
// See docs/WORDLIST_SOURCE.md for provenance.
export const WORDLIST: readonly string[] = [
  // ... all 7776 validated words, one per array entry, in source file order ...
];
```

- [ ] **Step 5: Write `docs/WORDLIST_SOURCE.md`**

```markdown
# Word List Provenance

- Source: EFF large wordlist (diceware), https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
- Fetched: 2026-07-21
- Entry count: 7776 (verified unique, lowercase ASCII)
- Used by: lib/passwordGenerator.ts passphrase mode
```

- [ ] **Step 6: Write the test**

`lib/wordlist.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { WORDLIST } from './wordlist';

describe('WORDLIST', () => {
  it('has exactly 7776 entries', () => {
    expect(WORDLIST.length).toBe(7776);
  });

  it('has no duplicate entries', () => {
    expect(new Set(WORDLIST).size).toBe(7776);
  });

  it('contains only lowercase ASCII words', () => {
    expect(WORDLIST.every((w) => /^[a-z]+(-[a-z]+)*$/.test(w))).toBe(true);
  });
});
```

- [ ] **Step 7: Run tests**

Run: `npx vitest run lib/wordlist.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 8: Commit**

```bash
git add lib/wordlist.ts lib/wordlist.test.ts docs/WORDLIST_SOURCE.md
git commit -m "feat: add validated EFF diceware word list for passphrase mode"
```

---

### Task 4: Password generator (charset + passphrase modes)

**Files:**
- Create: `lib/passwordGenerator.ts`
- Test: `lib/passwordGenerator.test.ts`

**Interfaces:**
- Consumes: `WORDLIST` from `lib/wordlist.ts` (Task 3).
- Produces: `secureRandInt(maxExclusive: number): number`, `generateCharsetPassword(opts: CharsetOptions): string`, `generatePassphrase(opts: PassphraseOptions, wordlist: readonly string[]): string` — consumed by `entrypoints/popup/VaultScreen.tsx` (Task 13).

- [ ] **Step 1: Write the failing tests**

`lib/passwordGenerator.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { secureRandInt, generateCharsetPassword, generatePassphrase } from './passwordGenerator';

describe('secureRandInt', () => {
  it('never returns a value >= maxExclusive across many samples', () => {
    for (let i = 0; i < 5000; i++) {
      const v = secureRandInt(37);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(37);
    }
  });

  it('throws for a non-positive bound', () => {
    expect(() => secureRandInt(0)).toThrow();
  });
});

describe('generateCharsetPassword', () => {
  it('generates a password of the requested length', () => {
    const pw = generateCharsetPassword({ length: 24, lower: true, upper: true, digits: true, symbols: true });
    expect(pw.length).toBe(24);
  });

  it('only uses enabled character classes', () => {
    const pw = generateCharsetPassword({ length: 40, lower: true, upper: false, digits: false, symbols: false });
    expect(pw).toMatch(/^[a-z]+$/);
  });

  it('rejects lengths outside 8-64', () => {
    expect(() => generateCharsetPassword({ length: 7, lower: true, upper: false, digits: false, symbols: false })).toThrow();
    expect(() => generateCharsetPassword({ length: 65, lower: true, upper: false, digits: false, symbols: false })).toThrow();
  });

  it('rejects when no character class is enabled', () => {
    expect(() => generateCharsetPassword({ length: 16, lower: false, upper: false, digits: false, symbols: false })).toThrow();
  });
});

describe('generatePassphrase', () => {
  const wordlist = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot'];

  it('generates the requested number of words, hyphen-joined', () => {
    const phrase = generatePassphrase({ wordCount: 6, capitalizeFirst: false, injectDigit: false, injectSymbol: false }, wordlist);
    expect(phrase.split('-')).toHaveLength(6);
  });

  it('capitalizes only the first word when requested', () => {
    const phrase = generatePassphrase({ wordCount: 3, capitalizeFirst: true, injectDigit: false, injectSymbol: false }, wordlist);
    const [first, ...rest] = phrase.split('-');
    expect(first[0]).toBe(first[0].toUpperCase());
    expect(rest.every((w) => w === w.toLowerCase())).toBe(true);
  });

  it('appends a trailing digit when requested', () => {
    const phrase = generatePassphrase({ wordCount: 3, capitalizeFirst: false, injectDigit: true, injectSymbol: false }, wordlist);
    expect(phrase).toMatch(/\d$/);
  });

  it('rejects wordCount outside 3-10', () => {
    expect(() => generatePassphrase({ wordCount: 2, capitalizeFirst: false, injectDigit: false, injectSymbol: false }, wordlist)).toThrow();
    expect(() => generatePassphrase({ wordCount: 11, capitalizeFirst: false, injectDigit: false, injectSymbol: false }, wordlist)).toThrow();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run lib/passwordGenerator.test.ts`
Expected: FAIL with "Cannot find module './passwordGenerator'".

- [ ] **Step 3: Write the implementation**

`lib/passwordGenerator.ts`:

```typescript
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';

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

export function generateCharsetPassword(opts: CharsetOptions): string {
  const { length, lower, upper, digits, symbols } = opts;
  if (length < 8 || length > 64) throw new Error('generateCharsetPassword: length must be between 8 and 64');
  let charset = '';
  if (lower) charset += LOWER;
  if (upper) charset += UPPER;
  if (digits) charset += DIGITS;
  if (symbols) charset += SYMBOLS;
  if (!charset) throw new Error('generateCharsetPassword: at least one character class must be enabled');
  let out = '';
  for (let i = 0; i < length; i++) {
    out += charset[secureRandInt(charset.length)];
  }
  return out;
}

export function generatePassphrase(opts: PassphraseOptions, wordlist: readonly string[]): string {
  const { wordCount, capitalizeFirst, injectDigit, injectSymbol } = opts;
  if (wordCount < 3 || wordCount > 10) throw new Error('generatePassphrase: wordCount must be between 3 and 10');
  if (wordlist.length === 0) throw new Error('generatePassphrase: wordlist must not be empty');
  const words: string[] = [];
  for (let i = 0; i < wordCount; i++) {
    words.push(wordlist[secureRandInt(wordlist.length)]);
  }
  if (capitalizeFirst) {
    words[0] = words[0][0].toUpperCase() + words[0].slice(1);
  }
  let phrase = words.join('-');
  if (injectDigit) phrase += String(secureRandInt(10));
  if (injectSymbol) phrase += SYMBOLS[secureRandInt(SYMBOLS.length)];
  return phrase;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/passwordGenerator.test.ts`
Expected: PASS (9 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/passwordGenerator.ts lib/passwordGenerator.test.ts
git commit -m "feat: add password generator (charset + passphrase modes)"
```

---

### Task 5: Relay fetch mechanism

**Files:**
- Create: `lib/relay.ts`
- Test: `lib/relay.test.ts`

**Interfaces:**
- Produces: `relayFetch(origin: string, path: string, init: RelayRequestInit, needsCsrf?: boolean): Promise<RelayResponse>`, `_resetRelayTabForTest(): void` — consumed by `lib/serverClient.ts` (Task 6).

- [ ] **Step 1: Write the failing tests**

`lib/relay.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';

const tabsCreate = vi.fn();
const tabsGet = vi.fn();
const tabsOnRemovedAddListener = vi.fn();
const tabsOnUpdatedAddListener = vi.fn();
const tabsOnUpdatedRemoveListener = vi.fn();
const scriptingExecuteScript = vi.fn();

vi.mock('wxt/browser', () => ({
  browser: {
    tabs: {
      create: tabsCreate,
      get: tabsGet,
      onRemoved: { addListener: tabsOnRemovedAddListener },
      onUpdated: { addListener: tabsOnUpdatedAddListener, removeListener: tabsOnUpdatedRemoveListener },
    },
    scripting: {
      executeScript: scriptingExecuteScript,
    },
  },
}));

import { relayFetch, _resetRelayTabForTest } from './relay';

beforeEach(() => {
  vi.clearAllMocks();
  _resetRelayTabForTest();
});

describe('relayFetch', () => {
  it('creates a pinned, inactive tab for the origin and injects the fetch', async () => {
    tabsCreate.mockResolvedValue({ id: 42, status: 'complete' });
    tabsGet.mockResolvedValue({ id: 42, status: 'complete' });
    scriptingExecuteScript.mockResolvedValue([{ result: { status: 200, headers: { 'x-vault-salt': 'abc' }, body: '{"ok":true}' } }]);

    const result = await relayFetch('https://vault.example.com', '/api/auth/login', { method: 'POST' });

    expect(tabsCreate).toHaveBeenCalledWith({ url: 'https://vault.example.com', active: false, pinned: true });
    expect(scriptingExecuteScript).toHaveBeenCalledWith(
      expect.objectContaining({ target: { tabId: 42 } }),
    );
    expect(result).toEqual({ status: 200, headers: { 'x-vault-salt': 'abc' }, body: '{"ok":true}' });
  });

  it('reuses an existing relay tab on a second call', async () => {
    tabsCreate.mockResolvedValue({ id: 7, status: 'complete' });
    tabsGet.mockResolvedValue({ id: 7, status: 'complete' });
    scriptingExecuteScript.mockResolvedValue([{ result: { status: 200, headers: {}, body: '{}' } }]);

    await relayFetch('https://vault.example.com', '/api/auth/crypto-salt', { method: 'POST' });
    await relayFetch('https://vault.example.com', '/api/vault/credentials', { method: 'GET' });

    expect(tabsCreate).toHaveBeenCalledTimes(1);
  });

  it('waits for the tab to finish loading before injecting', async () => {
    tabsCreate.mockResolvedValue({ id: 9, status: 'loading' });
    tabsGet.mockResolvedValue({ id: 9, status: 'loading' });
    let updatedListener: ((tabId: number, info: { status: string }) => void) | undefined;
    tabsOnUpdatedAddListener.mockImplementation((fn) => {
      updatedListener = fn;
    });
    scriptingExecuteScript.mockResolvedValue([{ result: { status: 200, headers: {}, body: '{}' } }]);

    const promise = relayFetch('https://vault.example.com', '/api/auth/crypto-salt', { method: 'POST' });
    expect(scriptingExecuteScript).not.toHaveBeenCalled();
    updatedListener?.(9, { status: 'complete' });
    await promise;

    expect(scriptingExecuteScript).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run lib/relay.test.ts`
Expected: FAIL with "Cannot find module './relay'".

- [ ] **Step 3: Write the implementation**

`lib/relay.ts`:

```typescript
import { browser } from 'wxt/browser';

export interface RelayResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface RelayRequestInit {
  method: 'GET' | 'POST' | 'PUT';
  headers?: Record<string, string>;
  body?: string;
}

const RELAY_HEADERS = ['x-vault-salt'];

let relayTabId: number | null = null;

async function waitForTabComplete(tabId: number): Promise<void> {
  const tab = await browser.tabs.get(tabId);
  if (tab.status === 'complete') return;
  await new Promise<void>((resolve) => {
    const listener = (updatedId: number, info: { status?: string }) => {
      if (updatedId === tabId && info.status === 'complete') {
        browser.tabs.onUpdated.removeListener(listener);
        resolve();
      }
    };
    browser.tabs.onUpdated.addListener(listener);
  });
}

async function getRelayTab(origin: string): Promise<number> {
  if (relayTabId !== null) {
    try {
      await browser.tabs.get(relayTabId);
      return relayTabId;
    } catch {
      relayTabId = null;
    }
  }
  const tab = await browser.tabs.create({ url: origin, active: false, pinned: true });
  if (tab.id === undefined) throw new Error('relay: failed to create relay tab');
  relayTabId = tab.id;
  browser.tabs.onRemoved.addListener((tabId: number) => {
    if (tabId === relayTabId) relayTabId = null;
  });
  await waitForTabComplete(relayTabId);
  return relayTabId;
}

/** Runs inside the relay tab's own page context via chrome.scripting.executeScript. */
function relayFetchInPage(path: string, init: RelayRequestInit, headerNames: string[], needsCsrf: boolean) {
  const finalInit: RequestInit = { ...init, credentials: 'include' };
  if (needsCsrf) {
    const match = document.cookie.match(/(?:^|; )_pwd_csrf=([^;]+)/);
    const csrf = match ? decodeURIComponent(match[1]) : '';
    finalInit.headers = { ...(finalInit.headers ?? {}), 'X-CSRF-Token': csrf };
  }
  return fetch(path, finalInit).then(async (res) => {
    const headers: Record<string, string> = {};
    for (const name of headerNames) {
      const value = res.headers.get(name);
      if (value !== null) headers[name] = value;
    }
    const body = await res.text();
    return { status: res.status, headers, body };
  });
}

export async function relayFetch(
  origin: string,
  path: string,
  init: RelayRequestInit,
  needsCsrf = false,
): Promise<RelayResponse> {
  const tabId = await getRelayTab(origin);
  const [{ result }] = await browser.scripting.executeScript({
    target: { tabId },
    func: relayFetchInPage,
    args: [path, init, RELAY_HEADERS, needsCsrf],
  });
  if (!result) throw new Error('relay: no result from injected script');
  return result as RelayResponse;
}

export function _resetRelayTabForTest(): void {
  relayTabId = null;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/relay.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/relay.ts lib/relay.test.ts
git commit -m "feat: add same-origin relay-tab fetch mechanism"
```

---

### Task 6: PWDnow server API client

**Files:**
- Create: `lib/serverClient.ts`
- Test: `lib/serverClient.test.ts`

**Interfaces:**
- Consumes: `relayFetch` from `lib/relay.ts` (Task 5).
- Produces: `login`, `loginFinish`, `fetchCryptoSalt`, `getVaultResource`, `putVaultResource` — consumed by `lib/session.ts` (Task 7).

- [ ] **Step 1: Write the failing tests**

`lib/serverClient.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';

const relayFetch = vi.fn();
vi.mock('./relay', () => ({ relayFetch }));

import { login, loginFinish, fetchCryptoSalt, getVaultResource, putVaultResource } from './serverClient';

beforeEach(() => {
  vi.clearAllMocks();
});

describe('login', () => {
  it('returns ok + cryptoSaltHex on full success', async () => {
    relayFetch.mockResolvedValue({ status: 200, headers: { 'x-vault-salt': 'aabbccddeeff00112233445566778899' }, body: '{"ok":true}' });
    const result = await login('https://vault.example.com', 'a@b.com', 'pw');
    expect(result).toEqual({ ok: true, cryptoSaltHex: 'aabbccddeeff00112233445566778899' });
  });

  it('returns mfa methods without a salt when MFA is required', async () => {
    relayFetch.mockResolvedValue({ status: 200, headers: {}, body: '{"ok":true,"partialToken":"pt","methods":["totp"]}' });
    const result = await login('https://vault.example.com', 'a@b.com', 'pw');
    expect(result.methods).toEqual(['totp']);
    expect(result.cryptoSaltHex).toBeUndefined();
  });

  it('surfaces invalid_credentials', async () => {
    relayFetch.mockResolvedValue({ status: 200, headers: {}, body: '{"ok":false,"error":"invalid_credentials"}' });
    const result = await login('https://vault.example.com', 'a@b.com', 'wrong');
    expect(result).toEqual({ ok: false, error: 'invalid_credentials', cryptoSaltHex: undefined });
  });

  it('defaults ok to false for a hardware-mfa-only 403 response', async () => {
    relayFetch.mockResolvedValue({ status: 403, headers: {}, body: '{"error":"hardware_mfa_requires_daemon"}' });
    const result = await login('https://vault.example.com', 'a@b.com', 'pw');
    expect(result.ok).toBe(false);
    expect(result.error).toBe('hardware_mfa_requires_daemon');
  });
});

describe('loginFinish', () => {
  it('completes MFA and returns the salt', async () => {
    relayFetch.mockResolvedValue({ status: 200, headers: { 'x-vault-salt': 'aabbccddeeff00112233445566778899' }, body: '{"ok":true}' });
    const result = await loginFinish('https://vault.example.com', 'pt', '123456');
    expect(result.ok).toBe(true);
    expect(result.cryptoSaltHex).toBe('aabbccddeeff00112233445566778899');
  });
});

describe('fetchCryptoSalt', () => {
  it('returns the salt header on 200', async () => {
    relayFetch.mockResolvedValue({ status: 200, headers: { 'x-vault-salt': 'aabbccddeeff00112233445566778899' }, body: '{}' });
    expect(await fetchCryptoSalt('https://vault.example.com')).toBe('aabbccddeeff00112233445566778899');
  });

  it('returns null on non-200', async () => {
    relayFetch.mockResolvedValue({ status: 401, headers: {}, body: '{}' });
    expect(await fetchCryptoSalt('https://vault.example.com')).toBeNull();
  });
});

describe('getVaultResource / putVaultResource', () => {
  it('extracts the data field on GET', async () => {
    relayFetch.mockResolvedValue({ status: 200, headers: {}, body: '{"data":"opaque-blob"}' });
    expect(await getVaultResource('https://vault.example.com', 'credentials')).toBe('opaque-blob');
  });

  it('throws on a non-200 GET', async () => {
    relayFetch.mockResolvedValue({ status: 500, headers: {}, body: '{}' });
    await expect(getVaultResource('https://vault.example.com', 'credentials')).rejects.toThrow();
  });

  it('PUTs with CSRF enabled', async () => {
    relayFetch.mockResolvedValue({ status: 200, headers: {}, body: '{}' });
    await putVaultResource('https://vault.example.com', 'credentials', 'new-blob');
    expect(relayFetch).toHaveBeenCalledWith(
      'https://vault.example.com',
      '/api/vault/credentials',
      expect.objectContaining({ method: 'PUT', body: JSON.stringify({ data: 'new-blob' }) }),
      true,
    );
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run lib/serverClient.test.ts`
Expected: FAIL with "Cannot find module './serverClient'".

- [ ] **Step 3: Write the implementation**

`lib/serverClient.ts`:

```typescript
import { relayFetch } from './relay';

export interface LoginResult {
  ok: boolean;
  error?: string;
  partialToken?: string;
  methods?: string[];
  cryptoSaltHex?: string;
}

interface RawLoginBody {
  ok?: boolean;
  error?: string;
  partialToken?: string;
  methods?: string[];
}

export async function login(origin: string, email: string, password: string): Promise<LoginResult> {
  const res = await relayFetch(origin, '/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const parsed = JSON.parse(res.body) as RawLoginBody;
  return {
    ok: parsed.ok ?? false,
    error: parsed.error,
    partialToken: parsed.partialToken,
    methods: parsed.methods,
    cryptoSaltHex: res.headers['x-vault-salt'],
  };
}

export async function loginFinish(origin: string, partialToken: string, code: string): Promise<LoginResult> {
  const res = await relayFetch(origin, '/login/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ partialToken, code }),
  });
  const parsed = JSON.parse(res.body) as RawLoginBody;
  return {
    ok: parsed.ok ?? false,
    error: parsed.error,
    cryptoSaltHex: res.headers['x-vault-salt'],
  };
}

export async function fetchCryptoSalt(origin: string): Promise<string | null> {
  const res = await relayFetch(origin, '/api/auth/crypto-salt', { method: 'POST' });
  if (res.status !== 200) return null;
  return res.headers['x-vault-salt'] ?? null;
}

export async function getVaultResource(origin: string, resource: 'credentials' | 'folders'): Promise<string> {
  const res = await relayFetch(origin, `/api/vault/${resource}`, { method: 'GET' });
  if (res.status !== 200) throw new Error(`getVaultResource(${resource}): server returned ${res.status}`);
  const parsed = JSON.parse(res.body) as { data: string };
  return parsed.data;
}

export async function putVaultResource(origin: string, resource: 'credentials' | 'folders', data: string): Promise<void> {
  const res = await relayFetch(
    origin,
    `/api/vault/${resource}`,
    { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ data }) },
    true,
  );
  if (res.status !== 200) throw new Error(`putVaultResource(${resource}): server returned ${res.status}`);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/serverClient.test.ts`
Expected: PASS (9 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/serverClient.ts lib/serverClient.test.ts
git commit -m "feat: add PWDnow server API client (login/mfa/vault CRUD)"
```

---

### Task 7: Message protocol + background session state machine

**Files:**
- Create: `lib/messages.ts`, `lib/session.ts`
- Test: `lib/session.test.ts`

**Interfaces:**
- Consumes: `deriveServerKey`/`encryptForServer`/`decryptFromServer` (Task 2), `login`/`loginFinish`/`fetchCryptoSalt`/`getVaultResource`/`putVaultResource` (Task 6).
- Produces: `ExtMessage`, `ExtResponse`, `Credential`, `Folder`, `NewCredentialInput` types; `connect`, `finishMfaLogin`, `getStatus`, `unlockWithPassword`, `getVault`, `saveCredential`, `disconnect`, `_resetSessionStateForTest` — consumed by `entrypoints/background.ts` (Task 8) and the popup (Tasks 11–12).

- [ ] **Step 1: Write `lib/messages.ts`**

```typescript
export interface Folder {
  id: string;
  label: string;
}

export interface Credential {
  id: string;
  service: string;
  url: string;
  username: string;
  password?: string;
  folderId: string;
}

export interface NewCredentialInput {
  service: string;
  url: string;
  username: string;
  password: string;
}

export type ExtMessage =
  | { type: 'connect'; origin: string; email: string; password: string }
  | { type: 'loginFinish'; password: string; code: string }
  | { type: 'getStatus' }
  | { type: 'getVault' }
  | { type: 'saveCredential'; credential: NewCredentialInput }
  | { type: 'disconnect' };

export type ExtResponse =
  | { type: 'connectResult'; ok: boolean; error?: string; mfaRequired?: boolean; methods?: string[] }
  | { type: 'status'; connected: boolean; unlocked: boolean; origin?: string; email?: string }
  | { type: 'vault'; credentials: Credential[]; folders: Folder[] }
  | { type: 'saveResult'; ok: boolean; error?: string }
  | { type: 'error'; error: string };
```

- [ ] **Step 2: Write the failing tests**

`lib/session.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';

const storageLocal = new Map<string, unknown>();
const storageSession = new Map<string, unknown>();

vi.mock('wxt/browser', () => ({
  browser: {
    storage: {
      local: {
        get: vi.fn(async (key: string) => ({ [key]: storageLocal.get(key) })),
        set: vi.fn(async (obj: Record<string, unknown>) => {
          for (const [k, v] of Object.entries(obj)) storageLocal.set(k, v);
        }),
        remove: vi.fn(async (key: string) => {
          storageLocal.delete(key);
        }),
      },
      session: {
        get: vi.fn(async (key: string) => ({ [key]: storageSession.get(key) })),
        set: vi.fn(async (obj: Record<string, unknown>) => {
          for (const [k, v] of Object.entries(obj)) storageSession.set(k, v);
        }),
        remove: vi.fn(async (key: string) => {
          storageSession.delete(key);
        }),
      },
    },
  },
}));

const login = vi.fn();
const loginFinish = vi.fn();
const fetchCryptoSalt = vi.fn();
const getVaultResource = vi.fn();
const putVaultResource = vi.fn();
vi.mock('./serverClient', () => ({ login, loginFinish, fetchCryptoSalt, getVaultResource, putVaultResource }));

import * as session from './session';

const SALT = 'aabbccddeeff00112233445566778899';

beforeEach(() => {
  vi.clearAllMocks();
  storageLocal.clear();
  storageSession.clear();
  session._resetSessionStateForTest();
});

describe('connect', () => {
  it('derives and stores the key on full login success', async () => {
    login.mockResolvedValue({ ok: true, cryptoSaltHex: SALT });
    const result = await session.connect('https://vault.example.com', 'a@b.com', 'correct horse battery staple');
    expect(result).toEqual({ ok: true });
    expect(storageSession.has('pwdnow_derived_key')).toBe(true);
    expect(storageLocal.get('pwdnow_config')).toEqual({ origin: 'https://vault.example.com', email: 'a@b.com' });
  });

  it('reports mfaRequired without storing a key', async () => {
    login.mockResolvedValue({ ok: true, methods: ['totp'], partialToken: 'pt' });
    const result = await session.connect('https://vault.example.com', 'a@b.com', 'pw');
    expect(result).toEqual({ ok: true, mfaRequired: true, methods: ['totp'] });
    expect(storageSession.has('pwdnow_derived_key')).toBe(false);
  });

  it('surfaces a login error', async () => {
    login.mockResolvedValue({ ok: false, error: 'invalid_credentials' });
    const result = await session.connect('https://vault.example.com', 'a@b.com', 'wrong');
    expect(result).toEqual({ ok: false, error: 'invalid_credentials' });
  });
});

describe('finishMfaLogin', () => {
  it('derives the key after a successful MFA code', async () => {
    login.mockResolvedValue({ ok: true, methods: ['totp'], partialToken: 'pt' });
    await session.connect('https://vault.example.com', 'a@b.com', 'correct horse battery staple');
    loginFinish.mockResolvedValue({ ok: true, cryptoSaltHex: SALT });
    const result = await session.finishMfaLogin('https://vault.example.com', 'correct horse battery staple', '123456');
    expect(result).toEqual({ ok: true });
    expect(storageSession.has('pwdnow_derived_key')).toBe(true);
  });

  it('errors when there is no pending MFA login', async () => {
    const result = await session.finishMfaLogin('https://vault.example.com', 'pw', '123456');
    expect(result).toEqual({ ok: false, error: 'no_pending_login' });
  });
});

describe('getStatus', () => {
  it('reports disconnected with no config', async () => {
    expect(await session.getStatus()).toEqual({ connected: false, unlocked: false });
  });

  it('reports connected+unlocked after a full connect', async () => {
    login.mockResolvedValue({ ok: true, cryptoSaltHex: SALT });
    await session.connect('https://vault.example.com', 'a@b.com', 'correct horse battery staple');
    expect(await session.getStatus()).toEqual({ connected: true, unlocked: true, origin: 'https://vault.example.com', email: 'a@b.com' });
  });
});

describe('getVault / saveCredential', () => {
  async function connectFresh() {
    login.mockResolvedValue({ ok: true, cryptoSaltHex: SALT });
    await session.connect('https://vault.example.com', 'a@b.com', 'correct horse battery staple');
  }

  it('decrypts credentials and folders', async () => {
    await connectFresh();
    const { encryptForServer, deriveServerKey } = await import('./crypto');
    const key = await deriveServerKey('correct horse battery staple', SALT);
    getVaultResource.mockImplementation(async (_origin: string, resource: string) => {
      if (resource === 'credentials') return encryptForServer(key, JSON.stringify([{ id: '1', service: 'x', url: 'https://x.com', username: 'u', folderId: 'f1' }]));
      return encryptForServer(key, JSON.stringify([{ id: 'f1', label: 'General' }]));
    });
    const vault = await session.getVault();
    expect(vault.credentials).toHaveLength(1);
    expect(vault.folders).toEqual([{ id: 'f1', label: 'General' }]);
  });

  it('appends a new credential defaulting to the first folder', async () => {
    await connectFresh();
    const { encryptForServer, decryptFromServer, deriveServerKey } = await import('./crypto');
    const key = await deriveServerKey('correct horse battery staple', SALT);
    getVaultResource.mockImplementation(async (_origin: string, resource: string) => {
      if (resource === 'credentials') return encryptForServer(key, JSON.stringify([]));
      return encryptForServer(key, JSON.stringify([{ id: 'f1', label: 'General' }]));
    });
    putVaultResource.mockImplementation(async () => {});
    await session.saveCredential({ service: 'newsite.com', url: 'https://newsite.com', username: 'me', password: 'p@ss' });
    const [, , putBlob] = putVaultResource.mock.calls[0];
    const decrypted = await decryptFromServer(key, putBlob);
    const creds = JSON.parse(decrypted!);
    expect(creds).toHaveLength(1);
    expect(creds[0]).toMatchObject({ service: 'newsite.com', folderId: 'f1', username: 'me', password: 'p@ss' });
  });

  it('throws when locked (no derived key)', async () => {
    await expect(session.getVault()).rejects.toThrow('not_connected');
  });
});

describe('disconnect', () => {
  it('clears both storage tiers', async () => {
    login.mockResolvedValue({ ok: true, cryptoSaltHex: SALT });
    await session.connect('https://vault.example.com', 'a@b.com', 'correct horse battery staple');
    await session.disconnect();
    expect(storageLocal.has('pwdnow_config')).toBe(false);
    expect(storageSession.has('pwdnow_derived_key')).toBe(false);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run lib/session.test.ts`
Expected: FAIL with "Cannot find module './session'".

- [ ] **Step 3: Write the implementation**

`lib/session.ts`:

```typescript
import { browser } from 'wxt/browser';
import { deriveServerKey, encryptForServer, decryptFromServer } from './crypto';
import { login, loginFinish, fetchCryptoSalt, getVaultResource, putVaultResource } from './serverClient';
import type { Credential, Folder, NewCredentialInput } from './messages';

const CONFIG_KEY = 'pwdnow_config';
const KEY_STORAGE_KEY = 'pwdnow_derived_key';

interface StoredConfig {
  origin: string;
  email: string;
}

let cachedKey: CryptoKey | null = null;
let pendingPartialToken: string | null = null;

async function loadConfig(): Promise<StoredConfig | null> {
  const result = await browser.storage.local.get(CONFIG_KEY);
  return (result[CONFIG_KEY] as StoredConfig | undefined) ?? null;
}

async function saveConfig(config: StoredConfig): Promise<void> {
  await browser.storage.local.set({ [CONFIG_KEY]: config });
}

async function loadKeyFromSessionStorage(): Promise<CryptoKey | null> {
  if (cachedKey) return cachedKey;
  const result = await browser.storage.session.get(KEY_STORAGE_KEY);
  const raw = result[KEY_STORAGE_KEY] as number[] | undefined;
  if (!raw) return null;
  cachedKey = await crypto.subtle.importKey('raw', new Uint8Array(raw), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  return cachedKey;
}

async function storeKey(key: CryptoKey): Promise<void> {
  cachedKey = key;
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
  await browser.storage.session.set({ [KEY_STORAGE_KEY]: Array.from(raw) });
}

export async function connect(
  origin: string,
  email: string,
  password: string,
): Promise<{ ok: boolean; error?: string; mfaRequired?: boolean; methods?: string[] }> {
  const result = await login(origin, email, password);
  if (!result.ok) return { ok: false, error: result.error ?? 'unknown_error' };
  if (result.methods && result.methods.length > 0) {
    pendingPartialToken = result.partialToken ?? null;
    await saveConfig({ origin, email });
    return { ok: true, mfaRequired: true, methods: result.methods };
  }
  if (!result.cryptoSaltHex) return { ok: false, error: 'missing_salt' };
  const key = await deriveServerKey(password, result.cryptoSaltHex);
  await storeKey(key);
  await saveConfig({ origin, email });
  return { ok: true };
}

export async function finishMfaLogin(
  origin: string,
  password: string,
  code: string,
): Promise<{ ok: boolean; error?: string }> {
  if (!pendingPartialToken) return { ok: false, error: 'no_pending_login' };
  const result = await loginFinish(origin, pendingPartialToken, code);
  pendingPartialToken = null;
  if (!result.ok) return { ok: false, error: result.error ?? 'unknown_error' };
  if (!result.cryptoSaltHex) return { ok: false, error: 'missing_salt' };
  const key = await deriveServerKey(password, result.cryptoSaltHex);
  await storeKey(key);
  return { ok: true };
}

export async function getStatus(): Promise<{ connected: boolean; unlocked: boolean; origin?: string; email?: string }> {
  const config = await loadConfig();
  if (!config) return { connected: false, unlocked: false };
  const key = await loadKeyFromSessionStorage();
  return { connected: true, unlocked: key !== null, origin: config.origin, email: config.email };
}

export async function unlockWithPassword(password: string): Promise<{ ok: boolean; error?: string }> {
  const config = await loadConfig();
  if (!config) return { ok: false, error: 'not_connected' };
  const saltHex = await fetchCryptoSalt(config.origin);
  if (!saltHex) return { ok: false, error: 'session_expired' };
  const key = await deriveServerKey(password, saltHex);
  await storeKey(key);
  return { ok: true };
}

async function requireConfigAndKey(): Promise<{ config: StoredConfig; key: CryptoKey }> {
  const config = await loadConfig();
  if (!config) throw new Error('not_connected');
  const key = await loadKeyFromSessionStorage();
  if (!key) throw new Error('not_connected');
  return { config, key };
}

export async function getVault(): Promise<{ credentials: Credential[]; folders: Folder[] }> {
  const { config, key } = await requireConfigAndKey();
  const [credBlob, folderBlob] = await Promise.all([
    getVaultResource(config.origin, 'credentials'),
    getVaultResource(config.origin, 'folders'),
  ]);
  const credJson = await decryptFromServer(key, credBlob);
  const folderJson = await decryptFromServer(key, folderBlob);
  if (credJson === null || folderJson === null) throw new Error('decrypt_failed');
  return {
    credentials: JSON.parse(credJson) as Credential[],
    folders: JSON.parse(folderJson) as Folder[],
  };
}

export async function saveCredential(input: NewCredentialInput): Promise<void> {
  const { config, key } = await requireConfigAndKey();
  const [credBlob, folderBlob] = await Promise.all([
    getVaultResource(config.origin, 'credentials'),
    getVaultResource(config.origin, 'folders'),
  ]);
  const credJson = await decryptFromServer(key, credBlob);
  const folderJson = await decryptFromServer(key, folderBlob);
  if (credJson === null || folderJson === null) throw new Error('decrypt_failed');
  const credentials = JSON.parse(credJson) as Credential[];
  const folders = JSON.parse(folderJson) as Folder[];
  if (folders.length === 0) throw new Error('no_folders');
  const newCredential: Credential = {
    id: crypto.randomUUID(),
    service: input.service,
    url: input.url,
    username: input.username,
    password: input.password,
    folderId: folders[0].id,
  };
  credentials.push(newCredential);
  const newBlob = await encryptForServer(key, JSON.stringify(credentials));
  await putVaultResource(config.origin, 'credentials', newBlob);
}

export async function disconnect(): Promise<void> {
  cachedKey = null;
  pendingPartialToken = null;
  await browser.storage.session.remove(KEY_STORAGE_KEY);
  await browser.storage.local.remove(CONFIG_KEY);
}

export function _resetSessionStateForTest(): void {
  cachedKey = null;
  pendingPartialToken = null;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/session.test.ts`
Expected: PASS (10 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/messages.ts lib/session.ts lib/session.test.ts
git commit -m "feat: add message protocol and background session state machine"
```

---

### Task 8: Background entrypoint wiring

**Files:**
- Modify: `entrypoints/background.ts`
- Test: `entrypoints/background.test.ts`

**Interfaces:**
- Consumes: everything exported from `lib/session.ts` (Task 7) and `ExtMessage`/`ExtResponse` from `lib/messages.ts` (Task 7).

- [ ] **Step 1: Write the failing test**

`entrypoints/background.test.ts`:

```typescript
import { describe, it, expect, vi } from 'vitest';

vi.mock('@/lib/session', () => ({
  connect: vi.fn(async () => ({ ok: true })),
  finishMfaLogin: vi.fn(async () => ({ ok: true })),
  getStatus: vi.fn(async () => ({ connected: true, unlocked: true })),
  getVault: vi.fn(async () => ({ credentials: [], folders: [] })),
  saveCredential: vi.fn(async () => undefined),
  disconnect: vi.fn(async () => undefined),
}));

import { handleMessage } from './background';

describe('handleMessage', () => {
  it('routes connect to session.connect', async () => {
    const response = await handleMessage({ type: 'connect', origin: 'https://x.com', email: 'a@b.com', password: 'pw' });
    expect(response).toEqual({ type: 'connectResult', ok: true });
  });

  it('routes getStatus to session.getStatus', async () => {
    const response = await handleMessage({ type: 'getStatus' });
    expect(response).toEqual({ type: 'status', connected: true, unlocked: true });
  });

  it('wraps thrown errors as an error response', async () => {
    const { getVault } = await import('@/lib/session');
    vi.mocked(getVault).mockRejectedValueOnce(new Error('not_connected'));
    const response = await handleMessage({ type: 'getVault' });
    expect(response).toEqual({ type: 'error', error: 'not_connected' });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run entrypoints/background.test.ts`
Expected: FAIL — `handleMessage` is not exported from `./background`.

- [ ] **Step 3: Write the implementation**

`entrypoints/background.ts`:

```typescript
import { browser } from 'wxt/browser';
import * as session from '@/lib/session';
import type { ExtMessage, ExtResponse } from '@/lib/messages';

export async function handleMessage(message: ExtMessage): Promise<ExtResponse> {
  try {
    switch (message.type) {
      case 'connect': {
        const result = await session.connect(message.origin, message.email, message.password);
        return { type: 'connectResult', ...result };
      }
      case 'loginFinish': {
        const status = await session.getStatus();
        if (!status.origin) return { type: 'connectResult', ok: false, error: 'not_connected' };
        const result = await session.finishMfaLogin(status.origin, message.password, message.code);
        return { type: 'connectResult', ok: result.ok, error: result.error };
      }
      case 'getStatus': {
        const status = await session.getStatus();
        return { type: 'status', ...status };
      }
      case 'getVault': {
        const vault = await session.getVault();
        return { type: 'vault', ...vault };
      }
      case 'saveCredential': {
        await session.saveCredential(message.credential);
        return { type: 'saveResult', ok: true };
      }
      case 'disconnect': {
        await session.disconnect();
        return { type: 'status', connected: false, unlocked: false };
      }
    }
  } catch (e) {
    return { type: 'error', error: e instanceof Error ? e.message : 'unknown_error' };
  }
}

export default defineBackground(() => {
  browser.runtime.onMessage.addListener((message: ExtMessage, _sender, sendResponse) => {
    handleMessage(message).then(sendResponse);
    return true;
  });
});
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run entrypoints/background.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add entrypoints/background.ts entrypoints/background.test.ts
git commit -m "feat: wire background message routing to the session state machine"
```

---

### Task 9: Active-tab hostname matching

**Files:**
- Create: `lib/matchCredentials.ts`
- Test: `lib/matchCredentials.test.ts`

**Interfaces:**
- Consumes: `Credential` type from `lib/messages.ts` (Task 7).
- Produces: `hostnameFromUrl(url: string): string | null`, `matchCredentialsForHostname(credentials: Credential[], hostname: string): Credential[]` — consumed by `entrypoints/popup/VaultScreen.tsx` (Task 13).

- [ ] **Step 1: Write the failing tests**

`lib/matchCredentials.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { hostnameFromUrl, matchCredentialsForHostname } from './matchCredentials';
import type { Credential } from './messages';

describe('hostnameFromUrl', () => {
  it('extracts the hostname', () => {
    expect(hostnameFromUrl('https://example.com/login?x=1')).toBe('example.com');
  });

  it('returns null for an invalid URL', () => {
    expect(hostnameFromUrl('not a url')).toBeNull();
  });
});

describe('matchCredentialsForHostname', () => {
  const credentials: Credential[] = [
    { id: '1', service: 'Example', url: 'https://example.com', username: 'a', folderId: 'f1' },
    { id: '2', service: 'Other', url: 'https://other.com', username: 'b', folderId: 'f1' },
  ];

  it('returns only credentials whose url hostname matches', () => {
    expect(matchCredentialsForHostname(credentials, 'example.com')).toEqual([credentials[0]]);
  });

  it('returns an empty array when nothing matches', () => {
    expect(matchCredentialsForHostname(credentials, 'nomatch.com')).toEqual([]);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run lib/matchCredentials.test.ts`
Expected: FAIL with "Cannot find module './matchCredentials'".

- [ ] **Step 3: Write the implementation**

`lib/matchCredentials.ts`:

```typescript
import type { Credential } from './messages';

export function hostnameFromUrl(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

export function matchCredentialsForHostname(credentials: Credential[], hostname: string): Credential[] {
  return credentials.filter((c) => hostnameFromUrl(c.url) === hostname);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/matchCredentials.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/matchCredentials.ts lib/matchCredentials.test.ts
git commit -m "feat: add active-tab hostname matching for credential lists"
```

---

### Task 10: Fill/read form script

**Files:**
- Create: `lib/fillScript.ts`
- Test: `lib/fillScript.test.ts`

**Interfaces:**
- Produces: `fillFormInPage(payload: FillPayload): boolean`, `readFormInPage(): ReadFormResult`, `findFirstMatch` — consumed by `entrypoints/popup/VaultScreen.tsx` (Task 13) via `browser.scripting.executeScript`.

- [ ] **Step 1: Write the failing tests**

`lib/fillScript.test.ts`:

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { fillFormInPage, readFormInPage } from './fillScript';

beforeEach(() => {
  document.body.innerHTML = '';
});

describe('fillFormInPage', () => {
  it('fills username and password inputs and dispatches events', () => {
    document.body.innerHTML = `
      <input type="email" id="email" />
      <input type="password" id="pw" />
    `;
    let inputEvents = 0;
    document.getElementById('pw')!.addEventListener('input', () => inputEvents++);

    const filled = fillFormInPage({ username: 'me@example.com', password: 's3cret' });

    expect(filled).toBe(true);
    expect((document.getElementById('email') as HTMLInputElement).value).toBe('me@example.com');
    expect((document.getElementById('pw') as HTMLInputElement).value).toBe('s3cret');
    expect(inputEvents).toBe(1);
  });

  it('returns false when there is no password field', () => {
    document.body.innerHTML = `<input type="text" id="notpw" />`;
    expect(fillFormInPage({ username: 'me', password: 'pw' })).toBe(false);
  });
});

describe('readFormInPage', () => {
  it('reads the current values of username and password inputs', () => {
    document.body.innerHTML = `
      <input type="email" id="email" value="a@b.com" />
      <input type="password" id="pw" value="typed-pw" />
    `;
    expect(readFormInPage()).toEqual({ username: 'a@b.com', password: 'typed-pw' });
  });

  it('returns empty strings when no fields are found', () => {
    document.body.innerHTML = '';
    expect(readFormInPage()).toEqual({ username: '', password: '' });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run lib/fillScript.test.ts`
Expected: FAIL with "Cannot find module './fillScript'".

- [ ] **Step 3: Write the implementation**

`lib/fillScript.ts`:

```typescript
export interface FillPayload {
  username: string;
  password: string;
}

export interface ReadFormResult {
  username: string;
  password: string;
}

const USERNAME_SELECTORS = [
  'input[autocomplete="username"]',
  'input[type="email"]',
  'input[name*="user" i]',
  'input[name*="email" i]',
  'input[id*="user" i]',
  'input[id*="email" i]',
];

const PASSWORD_SELECTORS = [
  'input[autocomplete="current-password"]',
  'input[autocomplete="new-password"]',
  'input[type="password"]',
];

export function findFirstMatch(doc: Document, selectors: string[]): HTMLInputElement | null {
  for (const selector of selectors) {
    const el = doc.querySelector<HTMLInputElement>(selector);
    if (el) return el;
  }
  return null;
}

function setNativeValue(el: HTMLInputElement, value: string): void {
  const proto = Object.getPrototypeOf(el) as object;
  const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
  setter?.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

/** Injected into the active tab via browser.scripting.executeScript. */
export function fillFormInPage(payload: FillPayload): boolean {
  const usernameInput = findFirstMatch(document, USERNAME_SELECTORS);
  const passwordInput = findFirstMatch(document, PASSWORD_SELECTORS);
  if (!passwordInput) return false;
  if (usernameInput) setNativeValue(usernameInput, payload.username);
  setNativeValue(passwordInput, payload.password);
  return true;
}

/** Injected into the active tab via browser.scripting.executeScript. */
export function readFormInPage(): ReadFormResult {
  const usernameInput = findFirstMatch(document, USERNAME_SELECTORS);
  const passwordInput = findFirstMatch(document, PASSWORD_SELECTORS);
  return {
    username: usernameInput?.value ?? '',
    password: passwordInput?.value ?? '',
  };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/fillScript.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/fillScript.ts lib/fillScript.test.ts
git commit -m "feat: add fill/read form-field helpers for active-tab injection"
```

---

### Task 11: User-facing error messages

**Files:**
- Create: `lib/errorMessages.ts`
- Test: `lib/errorMessages.test.ts`

**Interfaces:**
- Produces: `mapErrorMessage(code: string): string` — consumed by `entrypoints/popup/ConnectScreen.tsx` (Task 12) and `entrypoints/popup/VaultScreen.tsx` (Task 13), per spec §8: raw error codes (`invalid_credentials`, `hardware_mfa_requires_daemon`, etc.) must never be shown to the user directly.

- [ ] **Step 1: Write the failing tests**

`lib/errorMessages.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { mapErrorMessage } from './errorMessages';

describe('mapErrorMessage', () => {
  it('maps a known code to friendly text', () => {
    expect(mapErrorMessage('invalid_credentials')).toBe('Incorrect email or password.');
  });

  it('maps the hardware-MFA-unsupported code to an explanatory message', () => {
    expect(mapErrorMessage('hardware_mfa_requires_daemon')).toMatch(/hardware security key/);
  });

  it('falls back to a generic message for an unrecognized code', () => {
    expect(mapErrorMessage('some_future_unmapped_code')).toBe(mapErrorMessage('unknown_error'));
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run lib/errorMessages.test.ts`
Expected: FAIL with "Cannot find module './errorMessages'".

- [ ] **Step 3: Write the implementation**

`lib/errorMessages.ts`:

```typescript
const MESSAGES: Record<string, string> = {
  invalid_credentials: 'Incorrect email or password.',
  account_locked: 'This account is temporarily locked. Try again later.',
  too_many_requests: 'Too many attempts. Please wait and try again.',
  mfa_locked: 'Too many incorrect codes. Please wait and try again.',
  hardware_mfa_requires_daemon:
    'This account requires a hardware security key, which the extension does not support yet. Please use the PWDnow web app.',
  missing_salt: 'Could not complete login. Please try again.',
  permission_denied: 'PWDnow needs permission to talk to your server to connect.',
  not_connected: 'Connect to a PWDnow server first.',
  session_expired: 'Your session expired. Please reconnect.',
  decrypt_failed: 'Could not unlock your vault with that password.',
  no_folders: 'Create at least one folder in the PWDnow web app before saving from the extension.',
  nothing_to_save: 'Nothing to save — generate a password or fill in the form first.',
  save_failed: 'Could not save the credential. Please try again.',
  unexpected_response: 'Something went wrong. Please try again.',
  unknown_error: 'Something went wrong. Please try again.',
};

export function mapErrorMessage(code: string): string {
  return MESSAGES[code] ?? MESSAGES.unknown_error;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/errorMessages.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/errorMessages.ts lib/errorMessages.test.ts
git commit -m "feat: map internal error codes to user-facing messages"
```

---

### Task 12: Popup — Connect screen (login + MFA)

**Files:**
- Create: `entrypoints/popup/ConnectScreen.tsx`
- Test: `entrypoints/popup/ConnectScreen.test.tsx`

**Interfaces:**
- Consumes: `ExtMessage`/`ExtResponse` from `lib/messages.ts` (Task 7); sends messages via `browser.runtime.sendMessage` (handled by Task 8's background); `mapErrorMessage` from `lib/errorMessages.ts` (Task 11).
- Produces: `ConnectScreen` component with an `onConnected: () => void` prop — consumed by `App.tsx` (Task 13).

- [ ] **Step 1: Write the failing test**

`entrypoints/popup/ConnectScreen.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

const sendMessage = vi.fn();
const permissionsRequest = vi.fn();
vi.mock('wxt/browser', () => ({
  browser: {
    runtime: { sendMessage },
    permissions: { request: permissionsRequest },
  },
}));

import { ConnectScreen } from './ConnectScreen';

beforeEach(() => {
  vi.clearAllMocks();
  permissionsRequest.mockResolvedValue(true);
});

describe('ConnectScreen', () => {
  it('calls onConnected after a successful login with no MFA', async () => {
    sendMessage.mockResolvedValue({ type: 'connectResult', ok: true });
    const onConnected = vi.fn();
    render(<ConnectScreen onConnected={onConnected} />);

    fireEvent.change(screen.getByPlaceholderText('https://vault.example.com'), { target: { value: 'https://vault.example.com' } });
    fireEvent.change(screen.getByPlaceholderText('email'), { target: { value: 'a@b.com' } });
    fireEvent.change(screen.getByPlaceholderText('master password'), { target: { value: 'pw' } });
    fireEvent.click(screen.getByText('Connect'));

    await waitFor(() => expect(onConnected).toHaveBeenCalled());
    expect(permissionsRequest).toHaveBeenCalledWith({ origins: ['https://vault.example.com/*'] });
  });

  it('shows the MFA code screen when methods are returned', async () => {
    sendMessage.mockResolvedValue({ type: 'connectResult', ok: true, mfaRequired: true, methods: ['totp'] });
    render(<ConnectScreen onConnected={vi.fn()} />);

    fireEvent.change(screen.getByPlaceholderText('https://vault.example.com'), { target: { value: 'https://vault.example.com' } });
    fireEvent.change(screen.getByPlaceholderText('email'), { target: { value: 'a@b.com' } });
    fireEvent.change(screen.getByPlaceholderText('master password'), { target: { value: 'pw' } });
    fireEvent.click(screen.getByText('Connect'));

    await waitFor(() => expect(screen.getByText('Enter your totp code')).toBeInTheDocument());
  });

  it('shows an error message on invalid credentials', async () => {
    sendMessage.mockResolvedValue({ type: 'connectResult', ok: false, error: 'invalid_credentials' });
    render(<ConnectScreen onConnected={vi.fn()} />);

    fireEvent.change(screen.getByPlaceholderText('https://vault.example.com'), { target: { value: 'https://vault.example.com' } });
    fireEvent.change(screen.getByPlaceholderText('email'), { target: { value: 'a@b.com' } });
    fireEvent.change(screen.getByPlaceholderText('master password'), { target: { value: 'wrong' } });
    fireEvent.click(screen.getByText('Connect'));

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Incorrect email or password.'));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run entrypoints/popup/ConnectScreen.test.tsx`
Expected: FAIL with "Cannot find module './ConnectScreen'".

- [ ] **Step 3: Write the implementation**

`entrypoints/popup/ConnectScreen.tsx`:

```tsx
import { useState } from 'react';
import { browser } from 'wxt/browser';
import type { ExtMessage, ExtResponse } from '@/lib/messages';
import { mapErrorMessage } from '@/lib/errorMessages';

interface Props {
  onConnected: () => void;
}

export function ConnectScreen({ onConnected }: Props) {
  const [origin, setOrigin] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
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
    return (
      <div>
        <h2>Enter your {mfaMethods[0]} code</h2>
        <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" />
        <button disabled={busy} onClick={handleMfaSubmit}>Verify</button>
        {error && <p role="alert">{mapErrorMessage(error)}</p>}
      </div>
    );
  }

  return (
    <div>
      <h2>Connect to PWDnow</h2>
      <input value={origin} onChange={(e) => setOrigin(e.target.value)} placeholder="https://vault.example.com" />
      <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email" />
      <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" placeholder="master password" />
      <button disabled={busy || !origin || !email || !password} onClick={handleConnect}>Connect</button>
      {error && <p role="alert">{mapErrorMessage(error)}</p>}
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run entrypoints/popup/ConnectScreen.test.tsx`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add entrypoints/popup/ConnectScreen.tsx entrypoints/popup/ConnectScreen.test.tsx
git commit -m "feat: add popup Connect screen (login + MFA code entry)"
```

---

### Task 13: Popup — Vault screen (match/fill/generate/save) + App wiring + final build

**Files:**
- Create: `entrypoints/popup/VaultScreen.tsx`
- Modify: `entrypoints/popup/App.tsx`, `entrypoints/popup/App.test.tsx`
- Create: `docs/MANUAL_E2E_CHECKLIST.md`
- Test: `entrypoints/popup/VaultScreen.test.tsx`

**Interfaces:**
- Consumes: `matchCredentialsForHostname`/`hostnameFromUrl` (Task 9), `fillFormInPage`/`readFormInPage` (Task 10), `generateCharsetPassword` (Task 4), `ExtMessage`/`ExtResponse`/`Credential` (Task 7), `mapErrorMessage` (Task 11), `ConnectScreen` (Task 12).

- [ ] **Step 1: Write the failing test**

`entrypoints/popup/VaultScreen.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

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

import { VaultScreen } from './VaultScreen';

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

  it('injects fillFormInPage into the active tab on Fill', async () => {
    sendMessage.mockResolvedValue({
      type: 'vault',
      credentials: [{ id: '1', service: 'Example', url: 'https://example.com', username: 'alice', password: 'pw1', folderId: 'f1' }],
      folders: [{ id: 'f1', label: 'General' }],
    });
    executeScript.mockResolvedValue([{ result: true }]);

    render(<VaultScreen />);
    await waitFor(() => screen.getByText('alice'));
    fireEvent.click(screen.getByText('Fill'));

    await waitFor(() => expect(executeScript).toHaveBeenCalledWith(expect.objectContaining({ target: { tabId: 1 } })));
  });

  it('generates a password on Generate', async () => {
    sendMessage.mockResolvedValue({ type: 'vault', credentials: [], folders: [{ id: 'f1', label: 'General' }] });
    render(<VaultScreen />);
    await waitFor(() => screen.getByText('Generate'));
    fireEvent.click(screen.getByText('Generate'));
    await waitFor(() => expect(screen.getByTestId('generated-password').textContent).toHaveLength(24));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run entrypoints/popup/VaultScreen.test.tsx`
Expected: FAIL with "Cannot find module './VaultScreen'".

- [ ] **Step 3: Write the implementation**

`entrypoints/popup/VaultScreen.tsx`:

```tsx
import { useEffect, useState } from 'react';
import { browser } from 'wxt/browser';
import type { Credential, ExtMessage, ExtResponse } from '@/lib/messages';
import { matchCredentialsForHostname, hostnameFromUrl } from '@/lib/matchCredentials';
import { fillFormInPage, readFormInPage } from '@/lib/fillScript';
import { generateCharsetPassword } from '@/lib/passwordGenerator';
import { mapErrorMessage } from '@/lib/errorMessages';

export function VaultScreen() {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [hostname, setHostname] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [generated, setGenerated] = useState('');

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

  function handleGenerate() {
    setGenerated(generateCharsetPassword({ length: 24, lower: true, upper: true, digits: true, symbols: true }));
  }

  async function handleSave() {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !hostname) return;
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
      await loadVault();
    } else {
      setError(response.type === 'error' ? response.error : 'save_failed');
    }
  }

  const matched = hostname ? matchCredentialsForHostname(credentials, hostname) : [];

  return (
    <div>
      <h2>{hostname ?? 'PWDnow'}</h2>
      {error && <p role="alert">{mapErrorMessage(error)}</p>}
      <ul>
        {matched.map((c) => (
          <li key={c.id}>
            {c.username}
            <button onClick={() => handleFill(c)}>Fill</button>
          </li>
        ))}
      </ul>
      <button onClick={handleGenerate}>Generate</button>
      {generated && <p data-testid="generated-password">{generated}</p>}
      <button onClick={handleSave}>Save current form as new credential</button>
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run entrypoints/popup/VaultScreen.test.tsx`
Expected: PASS (3 tests).

- [ ] **Step 5: Wire `App.tsx` to switch between screens by connection status**

`entrypoints/popup/App.tsx`:

```tsx
import { useEffect, useState } from 'react';
import { browser } from 'wxt/browser';
import { ConnectScreen } from './ConnectScreen';
import { VaultScreen } from './VaultScreen';
import type { ExtMessage, ExtResponse } from '@/lib/messages';

export default function App() {
  const [connected, setConnected] = useState<boolean | null>(null);

  useEffect(() => {
    void checkStatus();
  }, []);

  async function checkStatus() {
    const message: ExtMessage = { type: 'getStatus' };
    const response = (await browser.runtime.sendMessage(message)) as ExtResponse;
    setConnected(response.type === 'status' && response.connected && response.unlocked);
  }

  if (connected === null) return <p>Loading…</p>;
  return connected ? <VaultScreen /> : <ConnectScreen onConnected={() => setConnected(true)} />;
}
```

- [ ] **Step 6: Update the Task 1 smoke test to match the new App**

`entrypoints/popup/App.test.tsx`:

```tsx
import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';

const sendMessage = vi.fn();
vi.mock('wxt/browser', () => ({
  browser: { runtime: { sendMessage } },
}));

import App from './App';

describe('App', () => {
  it('shows the Connect screen when not connected', async () => {
    sendMessage.mockResolvedValue({ type: 'status', connected: false, unlocked: false });
    render(<App />);
    await waitFor(() => expect(screen.getByText('Connect to PWDnow')).toBeInTheDocument());
  });
});
```

- [ ] **Step 7: Run the full test suite**

Run: `npm test`
Expected: all test files PASS.

- [ ] **Step 8: Write the manual E2E checklist**

`docs/MANUAL_E2E_CHECKLIST.md`:

```markdown
# Manual End-to-End Checklist

Run against a live PWDnow server-mode instance before considering a release ready. Automated tests cover the pure logic (crypto, password generator, matching, form helpers) and the message-routing/component logic with mocked browser APIs — this checklist covers what only a real browser can verify.

1. **Connect** — load the unpacked extension, open the popup, enter a real server URL/email/master password. Verify the host-permission prompt appears for exactly that origin, and after granting it, login succeeds.
2. **MFA login** — connect to an account with TOTP enabled; verify the code-entry screen appears and a correct code completes login.
3. **Hardware-key-only account** — connect to an account whose only MFA method is a hardware key; verify a clear "not supported" message appears (no raw error code).
4. **Match & Fill** — open a site with a saved credential, open the popup, verify only matching credentials are listed, click Fill, verify both fields populate and the site's own JS (React/Vue forms) recognizes the change.
5. **Generate** — click Generate, verify a 24-character password appears.
6. **Save** — on a new site's signup form, generate a password, fill it into the page manually or leave the popover to sync, click Save, verify a new credential appears in the PWDnow web app afterward.
7. **Session survival** — close and reopen the popup without restarting the browser; verify it's still connected (derived key survived in `chrome.storage.session`).
8. **Browser restart** — fully quit and relaunch the browser; verify the popup requires the master password again (session storage cleared).
9. **Cross-browser** — repeat steps 1, 4, and 5 in Chrome, Edge, and Firefox (`npm run dev:firefox` / `npm run build:firefox`).
```

- [ ] **Step 9: Verify the production build for both targets**

Run: `npm run build && npm run build:firefox`
Expected: both succeed, producing `.output/chrome-mv3/` and `.output/firefox-mv2-or-mv3/` (whichever WXT names it) with a valid `manifest.json` in each.

- [ ] **Step 10: Commit**

```bash
git add entrypoints/popup/VaultScreen.tsx entrypoints/popup/VaultScreen.test.tsx entrypoints/popup/App.tsx entrypoints/popup/App.test.tsx docs/MANUAL_E2E_CHECKLIST.md
git commit -m "feat: add popup Vault screen (match/fill/generate/save) and wire App"
```
