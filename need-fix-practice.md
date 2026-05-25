# `need-fix-practice.md` — Senior-Developer Code-Quality Review

> **Purpose.** A grounded, prioritized list of places where the code was written in a
> beginner / sloppy way and should be rewritten so the codebase reads as professional and
> clean. Each item is written so that a future LLM (or developer) can fix it **without
> re-investigating**: it states *where*, *what is wrong*, *why it matters*, and *how to fix it*
> with a concrete target shape.
>
> **Scope.** Reviewed `web/` (React 19 + Express) and `daemon/` (Rust). Every `file:line`
> reference below was read directly.
>
> **Discipline note.** This is a security-reviewed codebase. Many things that *look* like
> smells are deliberate and well-commented (see [§ Explicitly NOT bugs](#explicitly-not-bugs)).
> **Do not "fix" those.** Only the items in Tiers 1–3 are real problems.
>
> **Hard rule for whoever implements these:** these are refactors of a working,
> security-critical password manager. Do **not** change cryptographic behavior, the wire
> protocol, or the zero-knowledge boundary while cleaning up. Refactor structure, not
> semantics. Run `npm run lint` (`tsc --noEmit`), `npm run test`, and the
> `e2e/comprehensive-platform.spec.ts` regression after each tier.

---

## Severity legend

| Tier | Meaning |
|---|---|
| **T1** | God files — too large / too many responsibilities. Highest maintainability cost. |
| **T2** | Clear beginner anti-patterns. Several are security-adjacent (CSRF, master-password UX). |
| **T3** | Mature code with one structural improvement opportunity. Low priority. |

Each finding carries an **Effort** estimate (S / M / L / XL).

---

## Tier 1 — God files (structure & maintainability)

### T1-1 · `web/src/pages/Settings.tsx` is a 5,075-line component with 111 `useState` and 11 `useEffect`

**Where:** `web/src/pages/Settings.tsx` — a single `export default function Settings()` starting at line 53.

**What's wrong.** One React component owns **111** `useState` calls and **11** `useEffect`s. It mixes
profile editing, MFA enrollment (TOTP/HOTP/WebAuthn/passkey/platform), security modes (duress/travel/lockout),
recovery keys, audit log + sessions, share-link management, import/export, and account destruction — all in
one function body. This is the textbook "God Component."

**Why it matters.**
- No one can hold 111 state atoms in their head; every edit risks breaking an unrelated feature.
- Every state change re-renders the *entire* 5k-line tree.
- It is effectively untestable in isolation — you can only test it through the full page.
- Merge conflicts are guaranteed because everything lives in one file.

**How to fix.** Decompose by feature into sub-components, each owning its own state, composed by a thin
`Settings` shell that only handles layout/tab routing:

```
src/pages/Settings/
  index.tsx                 // thin shell: tabs + layout, ~150 lines
  ProfileSection.tsx        // localProfile, save, photo upload
  MfaSection.tsx            // TOTP/HOTP/WebAuthn/passkey/platform enrollment
  SecurityModesSection.tsx  // duress / travel / lockout
  RecoveryKeySection.tsx
  AuditLogModal.tsx         // sessions + events tabs
  SharesModal.tsx
  hooks/useProfileForm.ts   // extracts the profile state + dirty + save logic
  hooks/useMfaSetup.ts
  hooks/useAuditLog.ts
```

Move related `useState` clusters into the matching custom hook (e.g. all `totp*` state →
`useMfaSetup`). Target: no component over ~400 lines, no component over ~15 `useState`.

**Effort:** XL. Do this incrementally — extract one section per PR, keeping behavior identical, and run the
E2E regression after each extraction.

---

### T1-2 · `web/src/pages/AddCredential.tsx` — 1,829 lines, 50 `useState`

**Where:** `web/src/pages/AddCredential.tsx` (component-level `useState` pile).

**What's wrong.** A single add/edit-credential form holds 50 independent `useState` values for what is
conceptually **one form object**. Each field is its own piece of state with its own setter.

**Why it matters.** 50 setters means 50 ways to forget to reset/validate a field; the "dirty"/"reset"/
"populate from `initialData`" logic has to touch all of them by hand (see the `initialData` handling around
`AddCredential.tsx:221`).

**How to fix.** Replace the field-by-field `useState` with **one `useReducer`** over a typed form state:

```ts
type CredentialForm = {
  service: string; username: string; password: string;
  url: string; notes: string; folderId: string;
  kba: { question: string; answer: string };
  // ...
};
type FormAction =
  | { type: 'setField'; field: keyof CredentialForm; value: string }
  | { type: 'reset'; from?: Partial<CredentialForm> };

function formReducer(state: CredentialForm, action: FormAction): CredentialForm { /* ... */ }
```

Then split the JSX into section components (`<BasicFields/>`, `<SecurityQuestions/>`, `<TotpFields/>`,
`<CustomFields/>`) that receive `state` + `dispatch`. Populate-from-`initialData` becomes a single
`dispatch({ type: 'reset', from: initialData })`.

**Effort:** L.

---

### T1-3 · `web/auth.js` — 2,669-line module doing auth + vault CRUD + crypto + sessions

**Where:** `web/auth.js` (the `mountAuthAndVault` export and ~56 route handlers).

**What's wrong.** One CommonJS module contains all `/api/auth/*` routes, all `/api/vault/*` routes, JWE
session creation/validation, scrypt/argon2 password hashing, per-file AES-GCM encryption, CSRF middleware,
and rate-limit bookkeeping.

**Why it matters.** A 2.7k-line module is hard to navigate and review; auth logic and vault-storage logic
have different security properties and should not share a file. Unit-testing one concern means loading all of
them.

**How to fix.** Split along concern boundaries (keep the public `mountAuthAndVault(app)` signature so callers
don't change):

```
web/
  auth.js                 // thin: mountAuthAndVault() wires the routers + middleware
  routes/authRoutes.js    // register, login, logout, me, profile, password, 2FA, sessions
  routes/vaultRoutes.js   // folders, credentials, asset-holder, duress-config, mfa
  lib/session.js          // JWE issue/verify, JTI tracking, cookie helpers
  lib/fileCrypto.js       // HKDF per-file key + AES-256-GCM read/write (atomic rename)
  lib/csrf.js             // the CSRF middleware
```

**Keep what's already good:** `auth.js` already uses named constants (`SCRYPT_N = 1 << 17`,
`JWE_TTL_SECONDS`, `REGISTER_WINDOW_MS`, `PUBLIC_IP_CACHE_MS`) instead of magic numbers — preserve that
discipline in the split modules.

**Effort:** L. This is server-side; verify with the existing API/E2E tests after the split.

---

## Tier 2 — Clear beginner anti-patterns

### T2-4 · A security primitive (CSRF-token extraction) is copy-pasted **four times with behavioral drift**

**Where:**
- `web/src/utils/mfa.ts:65` — `function getCsrfToken()`
- `web/src/utils/securityModes.ts:215` — `function getCsrf()`
- `web/src/components/ShareModal.tsx:15` — `function getCsrfToken()`
- `web/src/components/EmergencyAccessModal.tsx:34` — `function getCsrfToken()`
- `web/src/pages/Settings.tsx:761` — inline arrow `const getCsrfToken = () => ...`
- Plus **raw `_pwd_csrf` cookie regex inlined** across ~17 files (`Login.tsx`, `Header.tsx`, `Sidebar.tsx`,
  `VaultContext.tsx`, `Vault.tsx`, `Register.tsx`, `Setup.tsx`, `ForgotPassword.tsx`, `AppLayout.tsx`,
  `router.tsx`, …).

**What's wrong.** The four named copies are **not identical**:

```ts
// mfa.ts            — no decodeURIComponent, returns ''
return document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('_pwd_csrf='))?.split('=')[1] ?? '';

// securityModes.ts  — DOES decodeURIComponent, returns null
return decodeURIComponent(cookie.split('=')[1]);   // and returns null when missing

// ShareModal.tsx    — .trim() on the value, no decode, returns ''
return ...?.split('=')[1]?.trim() ?? '';
```

So the same cookie can yield different values depending on which copy runs (relevant the moment the token
ever contains a URL-encoded character), and call sites disagree on `''` vs `null` for "missing."

**Why it matters.** This is the CSRF defense. A security primitive must have **exactly one** implementation;
divergent copies are how subtle auth bugs and inconsistent failure handling get introduced.

**How to fix.** Create one canonical helper and delete the rest:

```ts
// web/src/utils/api.ts
export function getCsrfToken(): string {
  if (typeof document === 'undefined') return '';
  const m = document.cookie.match(/(?:^|;\s*)_pwd_csrf=([^;]*)/);
  return m ? decodeURIComponent(m[1]) : '';   // decode once; consistent '' on miss
}
```

Replace all five named copies and the ~17 inline regexes with `import { getCsrfToken } from '@/utils/api'`.
Pick **one** contract (recommend: always `decodeURIComponent`, always return `''` on miss) and verify the
server-side CSRF check in `auth.js` matches that decoding.

**Effort:** M (one definition; mechanical migration of call sites). Run the E2E suite — CSRF affects every
mutation.

---

### T2-5 · No shared `fetch` wrapper — 54 call sites hand-roll credentials/CSRF/JSON/error handling

**Where:** 54 `fetch(` call sites across `src/`. Notably, `web/src/components/EmergencyAccessModal.tsx:36`
already defines a **local** `async function apiFetch(url, options)` — the right abstraction exists but was
never extracted or shared.

**What's wrong.** Every mutating request re-types the same boilerplate: `credentials: 'same-origin'`,
`'Content-Type': 'application/json'`, the `X-CSRF-Token` header, `JSON.stringify(body)`, and ad-hoc
`res.ok` / `res.json()` error handling. Copy-paste with inevitable drift (some sites forget `credentials`,
some forget CSRF, some swallow errors differently).

**Why it matters.** Cross-cutting concerns (auth cookies, CSRF, content negotiation, uniform error mapping)
belong in **one** function. Spreading them across 54 sites guarantees one will be wrong.

**How to fix.** Promote the existing `EmergencyAccessModal` `apiFetch` into a shared util and route all calls
through it:

```ts
// web/src/utils/api.ts
export async function apiFetch<T = unknown>(url: string, opts: RequestInit = {}): Promise<T> {
  const method = (opts.method ?? 'GET').toUpperCase();
  const mutating = method !== 'GET' && method !== 'HEAD';
  const headers = new Headers(opts.headers);
  if (opts.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  if (mutating) headers.set('X-CSRF-Token', getCsrfToken());
  const res = await fetch(url, { credentials: 'same-origin', ...opts, headers });
  if (!res.ok) throw new ApiError(res.status, await res.text().catch(() => ''));
  return res.status === 204 ? (undefined as T) : res.json();
}
```

Migrate the 54 sites; delete the local `apiFetch` in `EmergencyAccessModal.tsx`. (Leave the few non-API
`fetch` calls that hit external/`blob:` URLs alone.)

**Effort:** M–L.

---

### T2-6 · Native `prompt()` / `alert()` / `confirm()` — including collecting the **master password** via `prompt()`

**Where:**
- `web/src/pages/Settings.tsx:405` — `const pwd = prompt('Enter your master password to enable Touch ID / Windows Hello unlock for this device:')`
- `web/src/pages/Settings.tsx:412,420` — `alert(...)` (hardcoded English)
- `web/src/pages/Settings.tsx:788, 3151` — `confirm(...)` (these two **are** already wrapped in `t()`, so they need a styled modal but **not** new i18n keys)
- `web/src/components/CreateFolderModal.tsx:87` — `alert('Please upload a valid SVG file.')` (hardcoded English)

**What's wrong.** `prompt()` is being used to collect a **master password**:
- The input is **not masked** — the secret is shown in cleartext in a browser-chrome dialog.
- `prompt`/`alert`/`confirm` **block the JS event loop** and cannot be styled, themed, or made accessible.
- The strings are **hardcoded English**, which violates this repo's own rule (`CLAUDE.md`: *all user-facing
  strings use `useTranslation()`*). None of these go through `t()`.
- It looks unmistakably like prototype code in an otherwise polished product.

**Why it matters.** For a password manager, prompting for the master password in an unmasked native dialog is
both a UX failure and a poor security signal to the user. The hardcoded strings also break i18n for every
non-English locale this project ships (`ar, de, es, fr, hi, id, it, ja, ko, pt, ru, zh`).

**How to fix.**
- Replace the master-password `prompt()` with a small in-app modal containing a real
  `<input type="password">` (the app already has modal patterns, e.g. `CreateFolderModal`,
  `EmergencyAccessModal`).
- Replace `alert()` with the existing in-app notification system (`NotificationContext` /
  `NotificationDropdown`).
- Replace `confirm()` with a styled confirmation modal.
- Route **all** new strings through `t('settings.xxx', 'fallback')` and add keys to every file under
  `src/locales/` and `public/locales/`.

**Effort:** M.

---

### T2-7 · `JSON.stringify` deep-equality for dirty-checking (runs every render)

**Where:** `web/src/pages/Settings.tsx:70`

```ts
const hasChanges = JSON.stringify(localProfile) !== JSON.stringify(profile);
```

**What's wrong.** Using `JSON.stringify` to compare two objects for equality is a beginner pattern:
- It runs a full serialize of both objects **on every render**.
- It is **key-order dependent** — two objects that are semantically equal but with keys in a different order
  compare as different (e.g. after a server round-trip reorders fields), falsely showing "unsaved changes."
- It silently mishandles `undefined`, `Date`, `Map`, etc.

**Why it matters.** Correctness (false dirty state → spurious "unsaved changes" warnings) and a needless
serialize on the hot render path.

**How to fix.** Track dirtiness explicitly, or compare structurally with a memo:

```ts
// Option A — explicit dirty flag set by the field-change handler:
const [isDirty, setIsDirty] = useState(false);
const handleLocalProfileChange = (field, value) => { setLocalProfile(p => ({ ...p, [field]: value })); setIsDirty(true); };
// reset isDirty=false after a successful save / when profile prop changes.

// Option B — shallow compare of the known fields, memoized:
const hasChanges = useMemo(
  () => PROFILE_FIELDS.some(k => localProfile[k] !== profile[k]),
  [localProfile, profile],
);
```

**Effort:** S.

---

### T2-8 · Dead code silenced with `void` — and the same map duplicated across two files

**Where:**
- `web/src/components/Sidebar.tsx:47` defines `const ICON_MAP: Record<string, React.FC<any>> = {...}`, then
  line 59: `void ICON_MAP; // intentional retain — see comment above`.
- `web/src/pages/AddCredential.tsx:34` defines the **same** `ICON_MAP` again.
- A shared `web/src/utils/folderIcons.tsx` already exists for exactly this purpose.

**What's wrong.** In `Sidebar.tsx` the map is unused, and the unused-variable warning is suppressed with the
`void X;` trick instead of removing it. Dead code kept alive by a lint band-aid is a classic beginner move.
Worse, the identical map is **copy-pasted** into `AddCredential.tsx`, so the two will drift.

**Why it matters.** Dead code misleads readers ("this must be needed, it's referenced"), and the duplicate
guarantees the two icon sets fall out of sync.

**How to fix.**
- If `Sidebar`'s `ICON_MAP` is genuinely unused → **delete it** (and the `void ICON_MAP;` line).
- If both files need it → move the single source of truth into `src/utils/folderIcons.tsx` and
  `import { ICON_MAP } from '@/utils/folderIcons'` in both. Also replace `React.FC<any>` with a precise type:
  `Record<string, React.ComponentType<{ className?: string }>>`.

**Effort:** S.

---

### T2-9 · Duplicated Brave-browser detection

**Where:** `web/src/utils/sessionTracker.ts:27` and `web/src/pages/Login.tsx:596` contain the identical block:

```ts
if ((navigator as any).brave && typeof (navigator as any).brave.isBrave === 'function' && await (navigator as any).brave.isBrave()) { ... }
```

**What's wrong.** Copy-pasted browser-detection logic, including the same `(navigator as any)` cast repeated
three times in one expression.

**Why it matters.** Two copies = two places to fix when the detection changes; the triple `as any` is
untyped.

**How to fix.** One util:

```ts
// web/src/utils/browser.ts
interface BraveNavigator extends Navigator { brave?: { isBrave(): Promise<boolean> } }
export async function isBraveBrowser(): Promise<boolean> {
  const n = navigator as BraveNavigator;
  return !!n.brave && typeof n.brave.isBrave === 'function' && (await n.brave.isBrave());
}
```

Call `isBraveBrowser()` from both sites.

**Effort:** S.

---

### T2-10 · `any` used in production (non-test) code

**Where (the production ones — test files are fine to leave):**
- `web/src/pages/Settings.tsx:133` — `const [auditEvents, setAuditEvents] = useState<any[]>([])`
- `web/src/pages/Settings.tsx:139` — `const [shares, setShares] = useState<any[]>([])`
- `web/src/utils/daemonClient.ts:232` — `payload?: any`
- `web/src/layouts/AppLayout.tsx:98` — `const handleAddFolder = async (newFolder: any) => {`
- `web/src/crypto/keystore.ts:164` — `const data: any = {}`

**What's wrong.** `any` opts those values out of type-checking entirely, in a security-sensitive frontend
where the data shapes (audit events, share links, folders, keystore payloads) are known.

**Why it matters.** `any` is contagious — it disables autocomplete and lets typos / wrong-shape access
through silently. `newFolder: any` is especially bad because `Folder` is a defined type in `src/types.ts`.

**How to fix.**
- Declare interfaces and use them: `AuditEvent`, `ShareLink` (in `src/types.ts`), then
  `useState<AuditEvent[]>([])` / `useState<ShareLink[]>([])`.
- `handleAddFolder(newFolder: Folder)` — use the existing type.
- `daemonClient.request<T>(cmd, payload?: unknown, ...)` — `unknown` is the right "I accept anything but you
  must narrow it" type; the method is already generic over the response `T`.
- `keystore.ts:164` — type the persisted shape (e.g. `{ token?: string; localKey?: string; ... }`).

**Effort:** M.

---

### T2-11 · `console.*` left in runtime paths (50 occurrences), no logging abstraction

**Where:** 50 `console.{log,debug,warn,error}` calls across `src/`. Examples:
- `web/src/pages/Login.tsx:337` — `console.log('[Login] Published cryptoSalt to server')`
- `web/src/pages/Login.tsx:503,508,544,550,555` — derivation warnings
- `web/src/context/VaultContext.tsx` — many `console.error('[VaultContext] ...')`

**What's wrong.** Direct `console.*` sprinkled through production code: there's no central control over log
level, no way to silence in production, and login/crypto-flow logs (`'[Login] Published cryptoSalt...'`) are
mild information disclosure in the browser console.

**Why it matters.** In a privacy-focused product, the console should be quiet in production and never narrate
the auth/crypto flow. Genuine error logging is fine; informational `console.log` of security steps is not.

**How to fix.** Add a tiny logger and replace direct calls:

```ts
// web/src/utils/logger.ts
const DEV = import.meta.env.DEV;
export const logger = {
  debug: (...a: unknown[]) => { if (DEV) console.debug(...a); },
  warn:  (...a: unknown[]) => { if (DEV) console.warn(...a); },
  error: (...a: unknown[]) => { console.error(...a); }, // keep real errors
};
```

Replace `console.debug/log/warn` with `logger.*`; **delete** purely informational logs like the cryptoSalt
one. Keep `ErrorBoundary`'s `console.error` (it's a legitimate last-resort error sink).

**Effort:** M (mechanical).

---

## Tier 3 — Rust daemon (mature; one structural note)

### T3-12 · `DaemonState` is a 1,335-line / 58-method god struct

**Where:** `daemon/src/vault/state.rs` — `impl DaemonState`.

**What's wrong (mildly).** One struct owns KDF/rewrap, session issuance, brute-force lockout
(`check_unlock_lockout`, `record_failed_unlock`, `prune_lockout_map`), header sidecar I/O (`read_header`,
`write_header`, `calculate_header_hmac`), passkey/PQC/quick-unlock unlock paths, and forensic wipe.

**Why it's only T3 (and what to keep).** Unlike the web god files, this code is **well-structured**: it uses
the clean `pub fn foo()` → private `fn foo_inner()` split (e.g. `verify_master_password` /
`verify_master_password_inner`, `unlock_with_passkey` / `_inner`) so the public API and the testable core are
separated, and the IPC layer uses `auth_then!` / `with_db!` / `with_vmk_db!` macros to avoid boilerplate.
This is senior-level Rust. The only issue is breadth of responsibility in one struct.

**How to fix (optional).** If/when this file is touched again, consider extracting cohesive services that
`DaemonState` holds rather than implements directly:
- `SessionStore` — challenge nonces + session tokens + idle timer.
- `LockoutTracker` — the failed-attempt map and back-off schedule.
- `HeaderStore` — `read_header` / `write_header` / `calculate_header_hmac` / meta path.
- `KdfService` — `rewrap_vmk_with_current_kdf`, `sqlcipher_key`, `blind_index_key`.

Keep the `_inner` pattern and macros. **Lower priority than every web item above.**

**Effort:** L — only worth doing alongside other daemon work.

---

## Explicitly NOT bugs (do not "fix" these)

These look like smells but are intentional and documented. Changing them would *introduce* bugs or weaken
security:

- **`catch {}` blocks in `web/src/utils/securityModes.ts`** (lines 71, 104, 131, 136, 194, 232, 352, 371,
  377) and `fingerprint.ts` — deliberate "fall through to the next storage path" fallbacks, each preceded by
  an explanatory comment. The duress/travel config has a documented chicken-and-egg with the pre-login
  session key; swallowing the error and trying the next source is the design.
- **Raw-HTML injection via React's `dangerously…InnerHTML` prop** in `Sidebar.tsx`, `AddCredential.tsx`,
  `CreateFolderModal.tsx`, `ManageFolders.tsx` — **all** route through `sanitizeSvg()` (DOMPurify +
  `RETURN_TRUSTED_TYPE`). This is the *correct*, mandated pattern per `CLAUDE.md`; leave it.
- **`unwrap()` / `expect()` in the daemon** — the overwhelming majority are in `#[cfg(test)]` modules and
  `hibp.rs` tests; the few in runtime code (e.g. `main.rs:154` signal-handler setup at startup) are
  acceptable fail-fast points.
- **`as any` in `*.test.ts` files** (`securityModes.test.ts`, `p2wPadding.test.ts`) — test mocks; not
  production code.
- **Plaintext storage of the duress/travel password *hash*** — documented trade-off: it's a 256 MiB Argon2id
  PHC that only triggers a local wipe and must be readable pre-login. See the header comment in
  `securityModes.ts` (lines ~40–53). Intentional.

---

## Suggested execution order

1. **T2-4** (canonical `getCsrfToken`) and **T2-5** (shared `apiFetch`) first — they create the
   `src/utils/api.ts` foundation that many later edits build on, and they remove a real security-consistency
   risk. Run E2E after.
2. **T2-6 → T2-11** — the smaller, self-contained anti-patterns. Each is independently shippable.
3. **T1-1 / T1-2 / T1-3** — the god-file decompositions, one section per PR, behavior-preserving, E2E after
   each.
4. **T3-12** — only alongside other daemon work.

After every change: `npm run lint` · `npm run test` · `npx playwright test e2e/comprehensive-platform.spec.ts`.
