# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm install          # Install dependencies
npm run dev          # Dev server on port 3000 (Vite + HMR)
npm run build        # Production build to dist/
npm start            # Run Express server (serves dist/)
npm run test         # Run Vitest tests
npm run lint         # TypeScript type check (tsc --noEmit)
npm run clean        # Remove dist/

# PM2 production
npm run pm2:start    # Start clustered production server
npm run pm2:stop     # Stop production server
npm run pm2:restart  # Restart production server
npm run pm2:logs     # Tail PM2 logs
```

Run a single test file: `npx vitest run src/utils/crypto.test.ts`

## Environment

Copy `.env.example` to `.env`. `GEMINI_API_KEY` is injected into the frontend at build time via `vite.config.ts` `define`. `VAULT_ORIGIN` sets the allowed WebSocket origin for production (e.g. `https://vault.example.com`). `BIND_HOST` defaults to `127.0.0.1`; set to `0.0.0.0` for LAN access.

## Architecture

**Frontend:** React 19 SPA with TypeScript, Vite, Tailwind CSS 4, React Router v7.

**Backend:** `server.js` (Express) + `auth.js` together form the server. `server.js` handles static serving, CSP nonce injection, WebSocket proxy to the vault daemon, and setup-wizard endpoints. `auth.js` (`mountAuthAndVault`) mounts all `/api/auth/*` and `/api/vault/*` routes.

### Three Operating Modes

The app has three distinct operating modes depending on how the user authenticated:

| Mode | Auth mechanism | Vault storage | Guard check |
|------|---------------|---------------|-------------|
| **Daemon** | `daemon.unlock()` → session token in `SecureKeyStore` | All crypto in Rust daemon | `keyStore.hasToken` |
| **Server / Demo** | POST `/api/auth/login` → JWE cookie `_pwd_sess` | AES-256-GCM encrypted files in `auth_data/` | `_pwd_csrf` cookie present |
| **Unauthenticated** | — | — | Redirected to `/login` |

`VaultContext` detects the active mode via `hasServerSession()` (checks for `_pwd_csrf` cookie). When true, all vault reads/writes route to `/api/vault/*` REST endpoints instead of encrypted localStorage.

### Server-Side Auth (`auth.js`)

All server-side user data is stored in `auth_data/` as AES-256-GCM encrypted files (HKDF-derived keys, never stored in plaintext). Key facts:

- **Password hashing:** scrypt (N=2^17, r=8, p=1) — not PBKDF2. The browser-side `src/utils/crypto.ts` uses PBKDF2 but that is only for the daemon / localStorage fallback paths.
- **Sessions:** JWE tokens (`A256GCM`) issued at login, stored in `_pwd_sess` HttpOnly cookie (24h TTL). Active session JTIs tracked per-user for invalidation.
- **CSRF:** `_pwd_csrf` cookie is the non-HttpOnly half. All `POST/PUT/PATCH/DELETE` routes require `X-CSRF-Token` header matching the cookie value. VaultContext reads this cookie and sets the header automatically.
- **Session rolling:** Cookie refreshed every 15 minutes of activity.

### Security Architecture (server.js)

- **CSP nonce:** A fresh `randomBytes(16)` nonce is generated per request and injected into `index.html` via string replacement on `<script` tags. Helmet uses this nonce in `script-src`. Do not add `'unsafe-inline'` to script-src.
- **Trusted Types:** `require-trusted-types-for 'script'` is enforced. Permitted policies: `dompurify`, `react-dom`, `default`.
- **WebSocket origin check:** Daemon proxy at `/ws` validates the `Origin` header against `ALLOWED_WS_ORIGINS`. Add `VAULT_ORIGIN` env var for custom domains.
- **Setup token:** One-time `SETUP_TOKEN` (in memory only) guards `/api/setup-*` endpoints. Vended only to localhost callers while `.setup_complete` file is absent.

### State Management

Four React Context providers defined in `src/main.tsx`:

| Context | Hook | What it holds |
|---------|------|---------------|
| `VaultContext` | `useVault()` | All vault data; routes reads/writes to server API or encrypted localStorage |
| `UserContext` | `useUser()` | Current user profile; reloads from `/api/auth/me` or `daemon.getProfile()` |
| `ThemeContext` | `useTheme()` | `'light' \| 'dark' \| 'system'` + computed `isDark` |
| `NotificationContext` | `useNotification()` | In-app notifications, unread count |

`UserProvider` is nested inside `AppLayout` (not `main.tsx`), so it re-mounts on logout/login.

### Routes

Defined in `src/router.tsx`. Routes except `/login`, `/register`, `/forgot-password`, `/setup` are wrapped in `AppLayout`, which redirects to `/login` when `keyStore.hasToken` is false (daemon mode guard).

```
/login              Login
/register           Registration
/forgot-password    Password reset
/setup              First-run wizard
/vault              All credentials
/vault/:folderId    Credentials filtered by folder
/security           Breach Monitor (HIBP)
/settings           User settings + 2FA management
/manage-folders     Folder CRUD + drag-to-reorder
/dashboard          Analytics overview
/asset-holder       Reusable email/phone/U2F assets
```

### Patterns

**Adding a credential:** Call `addCredential()` from `useVault()`. The context handles persistence (server or local) and triggers a notification automatically.

**Folder icons:** Lucide icon names stored as strings in `Folder.iconName`. Custom SVGs in `Folder.customSvg` must be sanitized with DOMPurify before rendering.

**Animations:** The `motion` package is used throughout. Use `Reorder` for sortable lists.

**Path alias:** `@/` maps to the project root in both Vite and TypeScript config.

**i18n:** All user-facing strings use `useTranslation()` from i18next. Translation files: `src/locales/en.json` and `src/locales/fr.json`.

**Encrypted local storage:** `src/utils/localCrypto.ts` wraps localStorage with `@noble/ciphers` (XChaCha20-Poly1305). Never use `localStorage.getItem/setItem` directly for vault data; use `readDecryptedLocal` / `writeEncryptedLocal`.

## graphify

This project has a graphify knowledge graph at graphify-out/.

Rules:
- Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md for god nodes and community structure
- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files
- After modifying code files in this session, run `graphify update .` to keep the graph current (AST-only, no API cost)
