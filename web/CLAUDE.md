# PWDnow Web — Claude Code Instructions

## Operational Rules

<use_parallel_tool_calls>
If you intend to call multiple tools and there are no dependencies between the tool calls, make all of the independent tool calls in parallel. Prioritize calling tools simultaneously whenever the actions can be done in parallel rather than sequentially. For example, when reading 3 files, run 3 read tools in parallel. Maximize parallel tool calls wherever possible.
However, if some tool calls depend on previous calls to inform dependent values, do NOT call them in parallel — call them sequentially. Never use placeholders or guess missing parameters.
</use_parallel_tool_calls>

<investigate_before_answering>
Never speculate about code you have not opened. If the user references a file, you MUST read it before answering. Investigate relevant files BEFORE answering questions about the codebase. Never claim anything about code without reading it first.
</investigate_before_answering>

---

## Project Identity

PWDnow is a zero-knowledge, local-first password manager with two cooperating layers:

- **Layer 1 (Daemon)**: Rust binary (`daemon/`) — all cryptography, SQLCipher storage. Runs fully offline and exposes gRPC on `127.0.0.1:50051`.
- **Layer 2 (Web)**: This directory (`web/`). React 19 SPA + Express server, acting as a GUI and gRPC-over-HTTP proxy to the daemon at `/api/rpc`.

**Architecture document**: `web/architecture.md` — full threat model, key hierarchy diagrams, crypto choices.  
**Knowledge graph**: `web/graphify-out/GRAPH_REPORT.md` — before making architectural decisions, check this.  
After modifying source files, run `graphify update .` from `web/` to keep the graph current.

---

## Critical Security Directives

These are absolute rules. Never violate them.

| Rule | Detail |
|---|---|
| **Zero-Knowledge** | Frontend NEVER handles KEK, VMK, or DEK in any form. |
| **No Key Persistence** | NEVER store key material in React state, `localStorage`, `sessionStorage`, or IndexedDB. |
| **SecureKeyStore only** | Session token lives in `src/crypto/keystore.ts` JS private field `#token`. Cleared on logout, session expiry, and after a 5-minute grace period of the tab being hidden (a bounded `visibilitychange` timer — not immediate, so a page refresh isn't mistaken for a backgrounded tab). |
| **No plaintext vault writes** | `writeEncryptedLocal` silently no-ops if the session key is absent. Vault data is NEVER written in plaintext. |
| **SVG sanitization** | Any `customSvg` injected into innerHTML MUST go through `sanitizeSvg()` from `src/utils/sanitize.ts` (DOMPurify + RETURN_TRUSTED_TYPE). |
| **No unsafe-inline scripts** | CSP enforces `nonce-{per-request}` for scripts. Never add `'unsafe-inline'` to scriptSrc. |
| **No API keys in bundle** | Vite `define` must not bake secrets into the browser bundle (C-04). All external API calls go through server-side proxy. |
| **CSRF on all mutations** | Every state-changing fetch must include `X-CSRF-Token` header extracted from the `_pwd_csrf` cookie. |
| **DOMPurify Trusted Types** | A `default` Trusted Types policy is registered in `main.tsx`. All innerHTML assignments flow through DOMPurify automatically. |

---

## Three Operating Modes

| Mode | Auth mechanism | Vault storage | Guard |
|---|---|---|---|
| **Daemon** | `daemon.unlock()` → session token in `SecureKeyStore` | Rust daemon via gRPC bridge | `keyStore.hasToken === true` |
| **Server** | `POST /api/auth/login` → `_pwd_sess` + `_pwd_csrf` cookies | AES-256-GCM encrypted files in `auth_data/` | `_pwd_csrf` cookie present (JS-readable) |
| **Unauthenticated** | — | — | Redirect to `/login` |

**Mode detection** (in `VaultContext`): `hasServerSession()` reads `_pwd_csrf` from `document.cookie`. When true, all vault reads/writes route to `/api/vault/*` REST endpoints. When false, use `readDecryptedLocal` / `writeEncryptedLocal` (daemon or local demo mode).

---

## File Map

### Entry points
| File | Role |
|---|---|
| `src/main.tsx` | React root: Trusted Types policy, context providers, `RouterProvider` |
| `src/router.tsx` | All routes, lazy-loaded pages, `AuthedLayout` guard |
| `src/types.ts` | Core TypeScript types: `Folder`, `Credential`, `AssetHolder`, `Notification` |
| `src/i18n.ts` | i18next setup: `en`/`fr`, HTTP backend loads from `/locales/{{lng}}/translation.json` |
| `server.js` | Express: CSP nonce middleware, gRPC proxy (`/api/rpc`), setup API, static assets |
| `auth.js` | All `/api/auth/*` and `/api/vault/*` routes, JWE session management, scrypt hashing |
| `vite.config.ts` | Vite config: `@/` alias, manual chunks, sourcemaps off in prod |
| `ecosystem.config.cjs` | PM2 cluster config (all CPUs, 1 GB memory ceiling) |

### Pages (`src/pages/`)
| Page | Route | Purpose |
|---|---|---|
| `Login.tsx` | `/login` | Two-step flow: email → method (password/passkey/WebAuthn/TOTP/Email OTP) |
| `Register.tsx` | `/register` | New vault creation (daemon or server mode) |
| `ForgotPassword.tsx` | `/forgot-password` | Server-mode password reset |
| `Setup.tsx` | `/setup` | First-run setup wizard (localhost-only setup token) |
| `Vault.tsx` | `/vault`, `/vault/:folderId` | Credential list/search per folder |
| `Dashboard.tsx` | `/dashboard` | Overview stats |
| `BreachMonitor.tsx` | `/security` | HIBP offline breach check + TOTP credential display |
| `Settings.tsx` | `/settings` | Profile, MFA, security modes, import/export, session management |
| `ManageFolders.tsx` | `/manage-folders` | Folder CRUD + drag-to-reorder |
| `AssetHolder.tsx` | `/asset-holder` | Master list of emails/phones/U2F keys |
| `VaultHealth.tsx` | `/health` | Password strength analysis, reuse and common-password detection |
| `EmergencyRequest.tsx` | `/emergency/request/:token` | Trusted-contact emergency access request |
| `ShareView.tsx` | `/share/:shareId` | One-time credential viewing (AES-GCM via URL fragment key) |
| `NotFound.tsx` | `*` | 404 |
| `AddCredential.tsx` | (modal) | Add/edit credential form |

### Components (`src/components/`)
| Component | Purpose |
|---|---|
| `ErrorBoundary.tsx` | Global error boundary + `RouteErrorBoundary` for router |
| `Sidebar.tsx` | Navigation sidebar with folder list |
| `Header.tsx` | Top bar with search, notification bell, lock button |
| `PublicHeader.tsx` | Header for unauthenticated pages (login/register/setup) |
| `NotificationDropdown.tsx` | Notification bell dropdown |
| `NetworkStatus.tsx` | Online/offline banner |
| `CreateFolderModal.tsx` | New folder creation modal |
| `UserAvatar.tsx` | Profile picture display |
| `SEO.tsx` | `react-helmet-async` meta tags |
| `LanguageModal.tsx` | Language switcher |
| `PhoneCountrySelect.tsx` | Country code selector for phone numbers |
| `ShareModal.tsx` | Generate one-time credential share link |
| `EmergencyAccessModal.tsx` | Configure trusted-contact emergency access |

### Utilities (`src/utils/`)
| Util | Key exports |
|---|---|
| `daemonClient.ts` | `DaemonClient` class, `daemon` singleton, `WIPE_TICKET_KEY`, `HIBP_REQUEST_TIMEOUT_MS` |
| `localCrypto.ts` | `writeEncryptedLocal`, `readDecryptedLocal`, `encryptForServer`, `decryptFromServer` |
| `mfa.ts` | TOTP/HOTP/Email OTP/WebAuthn/Passkey/Platform auth, `MfaConfig`, `LoginHints` |
| `securityModes.ts` | `wipeVaultData`, `armDuressMode`, `enableTravelMode`, `disableTravelMode`, `recordFailedLoginAttempt` |
| `sanitize.ts` | `sanitizeSvg` |
| `clipboardGuard.ts` | `secureClipboard` — copies to clipboard, auto-clears after N seconds |
| `passwordStrength.ts` | `passwordScore` (0–5), `scoreLabel` |
| `importExport.ts` | Import/export to PWDnow/Bitwarden/1Password/NordPass formats |
| `sessionTracker.ts` | `recordSession`, `getSessions`, `clearOtherSessions`, `LoginSession` |
| `crypto.ts` | `generateUUID`, `hashPassword` |

### Crypto (`src/crypto/`)
| File | Key exports |
|---|---|
| `keystore.ts` | `SecureKeyStore`, `keyStore` (singleton), `deriveLocalKeys`, `deriveLocalKey`, `getOrCreateLocalKeySalt` |

### Contexts (`src/context/`)
| Context | Mount point | Purpose |
|---|---|---|
| `ThemeContext` | `main.tsx` (outermost) | Dark/light/system theme |
| `NotificationContext` | `main.tsx` | In-app notifications queue |
| `VaultContext` | `main.tsx` | Vault data (folders/credentials/assets), mode routing |
| `UserContext` | `AppLayout.tsx` | Profile data (re-mounts on login/logout) |

---

## Tech Stack

- **Framework**: React 19 + TypeScript + Vite 6
- **Styling**: Tailwind CSS v4 (via `@tailwindcss/vite`) — permitted and strictly used
- **Routing**: React Router v7 (`src/router.tsx`)
- **State**: React Context only — no Redux, no Zustand
- **Icons**: `lucide-react`
- **Animations**: `motion` (Framer Motion v12). Use `Reorder` for drag-to-reorder lists
- **i18n**: `react-i18next` + `i18next-http-backend`. Always use `useTranslation()` for UI strings
- **Crypto (browser)**: WebCrypto `subtle` (HTTPS/localhost) + `@noble/ciphers` fallback (plain HTTP) + `@noble/hashes` PBKDF2 fallback
- **Binary protocol**: `@msgpack/msgpack` for WebSocket frames to daemon
- **Server auth**: `jose` (JWE), Node.js `crypto.scryptSync` (N=2¹⁷)
- **Path alias**: `@/` → `web/` project root (Vite + tsconfig)

---

## Development Commands

```bash
npm install
npm run dev          # Vite dev server :3000 (HMR, no daemon needed)
npm run build        # Production build → dist/
npm start            # Express server (serves dist/ + auth + WS proxy)
npm run test         # Vitest unit tests (src/)
npx vitest run src/utils/crypto.test.ts   # single test file
npm run lint         # tsc --noEmit
npm run clean        # rm -rf dist

# PM2 (production)
npm run pm2:start    # cluster mode, all CPUs
npm run pm2:stop
npm run pm2:restart
npm run pm2:logs

# E2E (Playwright)
npx playwright test                             # all E2E tests
npx playwright test e2e/comprehensive-platform.spec.ts # Full platform walkthrough
npx playwright test --headed                    # with browser visible
# Tests live in web/e2e/; config at web/playwright.config.ts
```

---

## Comprehensive Platform Test

The `e2e/comprehensive-platform.spec.ts` test is the gold standard for regression testing. It performs a full walkthrough of the platform:
1. **Auth**: Success/failure flows, MFA handling.
2. **Navigation**: Security, Health, Asset Holder, Manage Folders.
3. **i18n**: Real-time language toggle (EN/FR) and UI text verification.
4. **Resources**: Folder CRUD, Asset Template saving.
5. **Duress Mode**: Forensic wipe trigger, verification of local destruction.
6. **Account Destruction**: Verifies account destruction (currently local-only) and attempted re-registration.

ALWAYS run this test before shipping significant frontend or auth-related changes.

**Environment** (`web/.env` from `.env.example`):
- `VAULT_SOCKET` — Unix socket path (default `/run/vault-daemon/vault.sock`)
- `VAULT_ORIGIN` — allowed WS origin in production
- `BIND_HOST` — bind address (default `127.0.0.1`)
- `GEMINI_API_KEY` — served via server-side proxy only, never in Vite define

---

## Adding Features

When adding a new vault resource or daemon command, touch all layers:

1. **Daemon (Rust)** — `daemon/src/ipc/protocol.rs` (add `Request`/`Response` variants) + `daemon/src/ipc/socket.rs` (add `dispatch()` arm)
2. **DaemonClient** — `src/utils/daemonClient.ts` — typed method on `DaemonClient`, include `session_token: this.token`
3. **Server REST** — `auth.js` `mountAuthAndVault()` — matching `/api/vault/<resource>` GET + PUT endpoints for server mode
4. **VaultContext** — `src/context/VaultContext.tsx` — expose action, branch on `daemonConnected` / `hasServerSession()`
5. **i18n** — add keys to `src/locales/en.json` and `src/locales/fr.json`

---

## LocalStorage Key Registry

Never add new localStorage keys without documenting them here. Vault keys use `writeEncryptedLocal`; config keys may use plain `setItem`.

| Key | Encrypted | Purpose |
|---|---|---|
| `vault_folders` | Yes (AES-GCM) | Demo/offline folders |
| `vault_credentials` | Yes (AES-GCM) | Demo/offline credentials |
| `vault_asset_holder` | Yes (AES-GCM) | Demo/offline asset holder |
| `mfa_config` | Yes (AES-GCM + HMAC) | MFA config cache (TOTP secrets etc.) |
| `login_sessions` | Yes (AES-GCM) | Login session history |
| `_pwdn_pk_hint` | Yes (AES-GCM) | Passkey credential ID hints |
| `_lk_salt` | No (public param) | PBKDF2 salt for local key derivation |
| `_sys_vk_tkv` | No | Forensic wipe capability token (hex) |
| `_cache_local_xvc` | Yes (travel key) | Travel mode hidden vault ciphertext |
| `duress_mode_config` | No | Duress mode armed state + hashed password |
| `login_lockout_config` | No | Lockout counter + expiry |
| `_tm_cfg` | No | Travel mode state + hashed password (intentionally non-descriptive key name, same rationale as `_cache_local_xvc` — see `securityModes.ts`) |

---

## Encrypted Local Storage Format

All vault data written by `writeEncryptedLocal` uses a compact JWT-like token:

```
BASE64URL(header) . BASE64URL(iv || ciphertext+tag) . BASE64URL(HMAC-SHA256)
```

- Header: `{"v":"1","alg":"A256GCM+HS256"}` (static)
- Keys derived via single PBKDF2 pass (310 000 iterations, SHA-256, 64 bytes):
  - bytes 0–31 → AES-GCM-256 encryption key (`keyStore.getLocalKey()`)
  - bytes 32–63 → HMAC-SHA256 signing key (`keyStore.getSigningKey()`)
- Legacy format `{"enc":1,"iv":"...","ct":"..."}` is still transparently decrypted
- If the session key is absent, `writeEncryptedLocal` is a silent no-op

---

## IPC / DaemonClient Model

- WebSocket proxy at `/ws` — each browser tab gets one Unix socket connection to the daemon
- Protocol: binary msgpack frames, 4-byte big-endian length-prefix
- **FIFO queue**: requests are one-at-a-time. Only one `request()` in-flight per `DaemonClient` instance
- **On timeout**: the entire WebSocket is torn down (not just the pending request) because responses are matched positionally. The caller must reconnect
- **Error sanitization**: internal codes (`InvalidPassword`, `VaultLocked`, etc.) are mapped to safe UI strings via `SAFE_MESSAGES` (MED-06)
- **Connect guard**: after a failed connect, `#unavailableUntil` fast-rejects for 30 s
- **Custom events**:
  - `daemonUnlocked` (window) — fired after `daemon.unlock()` in Login; VaultContext reloads from daemon
  - `demoKeyAvailable` (window) — fired when PBKDF2 key becomes available; VaultContext re-decrypts localStorage

---

## MFA Architecture

`src/utils/mfa.ts` manages two storage layers for `MfaConfig`:

1. **In-memory cache** (`_mfaCache`) — live working copy, read synchronously via `getMfaConfig()`
2. **Encrypted localStorage** — written on every `saveMfaConfig()` call
3. **Server vault** — `saveMfaConfigToServer()` syncs to `/api/vault/mfa` (server mode only)

Login hints come **live from the daemon/server per email-step** — never persisted to localStorage (would leak which MFA methods are enrolled to an attacker).

After `saveMfaConfig()`, `daemon.updateLoginPolicy()` is called to sync `password_login_enabled`, `totp_enabled`, `email_otp_enabled` to the sidecar (daemon source of truth at login time).

Call `clearMfaCache()` on logout.

**MFA types**:
- `totp` — TOTP (RFC 6238), replay-protected via `_usedTotpPeriods` map
- `hotp` — HOTP (RFC 4226), lookahead=10
- `email` — In-memory OTP simulation, 5 min TTL, single-use
- `webauthn` — Cross-platform hardware keys (YubiKey) via daemon FIDO2
- `passkey` — Synced platform passkeys (iCloud/Google), residentKey required
- `platform` — Device-bound biometrics (Touch ID, Windows Hello), residentKey discouraged

---

## Security Modes (`src/utils/securityModes.ts`)

| Mode | Key function | What it does |
|---|---|---|
| **Duress mode** | `armDuressMode(password, maxAttempts)` | Alternate password triggers forensic wipe after N failures |
| **Travel mode** | `enableTravelMode(password, folderIds, ...)` | Hides folders behind PBKDF2-AES-GCM encryption; visible vault is the safe-to-show subset |
| **Lockout** | `recordFailedLoginAttempt()` | Tracks failed logins; locks for `lockoutDurationMins` after `maxAttempts` failures |
| **Forensic wipe** | `wipeVaultData(daemonInstance?)` | Phase 1: daemon 7-pass overwrite; Phase 2: browser 3-pass CSPRNG overwrite + `localStorage.clear()` + IndexedDB + caches |

Travel mode crypto uses PBKDF2-SHA256 (120 000 iterations) → AES-GCM-256. Falls back from WebCrypto `subtle` to `@noble/ciphers` on plain HTTP.

---

## Server-Side Auth (`auth.js`)

- Password hashing: `scryptSync` (N=2¹⁷, r=8, p=1, keylen=64)
- Sessions: JWE tokens (`A256GCM`, 24 h TTL). Active JTIs tracked per user for invalidation
- Session cookies: `_pwd_sess` (HttpOnly) + `_pwd_csrf` (JS-readable, used for CSRF detection)
- CSRF: `X-CSRF-Token` header required on all state-changing methods; value read from `_pwd_csrf` cookie
- Session rolling: cookie refreshed every 15 min of activity
- File storage: `auth_data/vault/<uid>/<resource>.enc` — AES-256-GCM with HKDF-SHA256 per-file key from `auth_data/.master_key`
- Atomic writes: `writeFileSync(tmp)` then `renameSync(tmp, final)` — no partial write vulnerability
- Vault resources per user: `credentials.enc`, `folders.enc`, `asset_holder.enc`, `sessions.enc`, `profile.enc`, `mfa_config.enc`

---

## CSP and Trusted Types

`server.js` injects a fresh 16-byte base64 nonce per request as `res.locals.cspNonce`. Directives:

```
default-src 'none'
script-src  'self' 'nonce-{nonce}'
style-src   'self' 'unsafe-inline'   ← Tailwind CSS requirement (HIGH-08 tracked)
font-src    'self'
img-src     'self' blob:
connect-src 'self' ws: wss: https://api.pwnedpasswords.com
form-action 'self'
frame-ancestors 'none'
base-uri 'none'
object-src 'none'
require-trusted-types-for 'script'
```

The `default` Trusted Types policy in `main.tsx` routes all innerHTML through `DOMPurify.sanitize`. `createScript` and `createScriptURL` are blocked unconditionally.

---

## VaultHeader Sidecar (daemon-side)

`vault.db.meta` is a plaintext JSON sidecar the daemon reads before unlock. Fields: `vault_uuid`, `argon2_salt`, `encrypted_vmk`, `vmk_nonce`, `password_login_enabled`, `totp_enabled`, `email_otp_enabled`, `passkey_credentials`, `wipe_ticket`.

The unauthenticated `GetLoginHints` IPC command reads it. It is the source of truth for the frontend login policy. `daemon.updateLoginPolicy()` writes to it via the authenticated `UpdateLoginPolicy` command.

---

## Passkey / FIDO2 Login Flow (daemon mode)

1. `daemon.getLoginHints()` → `{ fido2_ids, password_login_enabled, ... }` (no auth needed)
2. `daemon.getPasskeyChallenge()` → 32-byte random challenge (server-side, consumed once)
3. `navigator.credentials.get(...)` with challenge + `allowCredentials` from step 1
4. `daemon.unlockWithPasskey(credentialId, authData, signature)` → decrypts VMK copy, issues session token

Implemented in `authenticateWebAuthnForLogin()` in `src/utils/mfa.ts`.

---

## Clipboard Security

Use `secureClipboard()` from `src/utils/clipboardGuard.ts` for all password copy operations. It uses `execCommand('copy')` (avoids Chrome permission bar), auto-clears after N seconds (default 10), and returns a `cancel()` handle.

---

## Import / Export

`src/utils/importExport.ts` supports four formats: `pwdnow` (JSON), `bitwarden` (CSV), `1password` (CSV), `nordpass` (CSV). Autodetects format on import. Use `triggerDownload()` to initiate download, `importFromFile()` to parse.

---

## i18n Rules

- Always wrap user-facing strings in `useTranslation()` → `t('key', 'fallback')`
- Translation files: `src/locales/en.json` (source of truth) and `src/locales/fr.json`
- Served from `/locales/{{lng}}/translation.json` at runtime (i18next HTTP backend)
- When adding a new string, add it to both files simultaneously

---

## Graphify

Run `graphify update .` from `web/` after modifying source files to keep the AST knowledge graph current. Before answering architecture or codebase questions, check `graphify-out/GRAPH_REPORT.md` for god nodes and community structure.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
