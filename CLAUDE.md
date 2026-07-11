# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Operational Rules

<use_parallel_tool_calls>
If you intend to call multiple tools and there are no dependencies between the tool calls, make all of the independent tool calls in parallel. Prioritize calling tools simultaneously whenever the actions can be done in parallel rather than sequentially. For example, when reading 3 files, run 3 tool calls in parallel to read all 3 files into context at the same time. Maximize use of parallel tool calls where possible to increase speed and efficiency.
However, if some tool calls depend on previous calls to inform dependent values like the parameters, do NOT call these tools in parallel and instead call them sequentially. Never use placeholders or guess missing parameters in tool calls.
</use_parallel_tool_calls>

<investigate_before_answering>
Never speculate about code you have not opened. If the user references a specific file, you MUST read the file before answering. Make sure to investigate and read relevant files BEFORE answering questions about the codebase. Never make any claims about code before investigating unless you are certain of the correct answer - give grounded and hallucination-free answers.
</investigate_before_answering>

## Repository Layout

```
PWDnow/
├── daemon/        Rust vault daemon (Layer 1 — all cryptography lives here)
├── web/           React 19 + Express frontend/proxy (Layer 2)
├── deploy/        systemd unit, AppArmor profile, Nginx config, Makefile
└── hibp/          Script to build offline HIBP Cuckoo-filter
```

A per-directory `web/CLAUDE.md` exists and covers web-specific commands and patterns in more detail.

---

## Commands

### Full project (from `deploy/`)

```bash
make build          # cargo build --release + npm run build
make build-pq       # same but with --features pq (ML-KEM-768 hybrid KEM)
make test           # cargo test + vitest run
make lint           # cargo clippy -D warnings + tsc --noEmit
make install        # installs binary, systemd, AppArmor, nginx (needs sudo)
```

### Daemon (from `daemon/`)

```bash
cargo build --release
cargo build --release --features pq   # post-quantum KEM enabled
cargo test
cargo test -- <test_name>             # run a single test
cargo clippy -- -D warnings
```

### Web frontend (from `web/`)

```bash
npm run dev        # Vite dev server on :3000 (HMR, no daemon needed)
npm run build      # production build → dist/
npm start          # Express server serving dist/ + gRPC bridge
npm run test       # vitest run (all)
npx vitest run src/utils/crypto.test.ts   # single test file
npm run lint       # tsc --noEmit
npm run clean      # remove dist/

# PM2 production
npm run pm2:start    # clustered production server
npm run pm2:stop
npm run pm2:restart
npm run pm2:logs
```

### Environment (from `web/`)

Copy `.env.example` to `.env`. Key variables:
- `DAEMON_GRPC_ADDR` — Daemon gRPC address (default `127.0.0.1:50051`)
- `VAULT_ORIGIN` — allowed origin for production (e.g. `https://vault.example.com`)
- `BIND_HOST` — defaults to `127.0.0.1`; set to `0.0.0.0` for LAN access

---

## Two-Layer Architecture

The system has two completely separate codebases that cooperate at runtime.

### Layer 1 — Vault Daemon (`daemon/`)

Rust binary: `vault-daemon`. All cryptographic operations happen here; the web layer never sees keys or plaintext.

**Key hierarchy** (offline/local mode):
```
master_password + YubiKey HMAC-SHA256  →  Argon2id  →  512-bit master material
  [0..255]  KEK  →  decrypt VMK from SQLite (XChaCha20-Poly1305)
  VMK       →  decrypt per-credential DEK  →  decrypt credential blob
```

**IPC**: gRPC on `127.0.0.1:50051`. Protocol defined in `proto/vault.proto`.

**Session tokens**: issued at unlock, passed in metadata in every authenticated request. Token tied to UID and auto-expires after 15 minutes of idle.

**Key modules**:
- `daemon/src/ipc/grpc_server.rs` — gRPC implementation, `VaultService`
- `daemon/src/ipc/protocol.rs` — Request/Response mapping to gRPC types
- `daemon/src/vault/state.rs` — `DaemonState`, mlock'd VMK, session store, idle timer
- `daemon/src/crypto/` — Argon2id, XChaCha20-Poly1305, AES-GCM, X25519/ML-KEM KEM, HIBP Cuckoo filter
- `daemon/src/vault/credentials.rs` — encrypted credential CRUD with per-item DEKs
- `daemon/src/auth/session.rs` — session token issuance and validation

**Build features**: `--features pq` enables the `ml-kem` crate for hybrid X25519+ML-KEM-768 KEM (post-quantum VMK encapsulation). `--features mock-fido2` replaces real libfido2 with a stub for CI.

### Layer 2 — Web (`web/`)

Express server (`server.js` + `auth.js`) + React 19 SPA.

**Three operating modes** depending on how the user authenticated:

| Mode | Auth mechanism | Vault storage | Guard check |
|---|---|---|---|
| **Daemon** | WebSocket `daemon.unlock()` → session token in `SecureKeyStore` | All crypto in Rust daemon | `keyStore.hasToken` |
| **Server / Demo** | POST `/api/auth/login` → JWE cookie `_pwd_sess` | AES-256-GCM encrypted files in `auth_data/` | `_pwd_csrf` cookie present |
| **Unauthenticated** | — | — | Redirected to `/login` |

Mode is detected in `VaultContext` via `hasServerSession()` (checks for the non-HttpOnly `_pwd_csrf` cookie). When true, all vault reads/writes route to `/api/vault/*` REST endpoints instead of encrypted localStorage.

**`server.js` responsibilities**:
1. Serves the `dist/` SPA build with per-request CSP nonce injection into `index.html`
2. WebSocket proxy at `/ws`: each browser WS connection gets one Unix socket connection to the daemon; msgpack frames are forwarded bidirectionally
3. Setup API endpoints (`/api/setup-token`, `/api/setup-complete`, `/api/system-info`, `/api/ubuntu-pro/*`) — protected by an in-memory `SETUP_TOKEN` vended only to localhost callers

**`auth.js` responsibilities** (`mountAuthAndVault`):
- All `/api/auth/*` routes: register, login, logout, `/api/auth/me`, profile, password change, 2FA, sessions
- All `/api/vault/*` routes: folders, credentials, asset-holder (REST CRUD backed by per-user encrypted files in `auth_data/vault/<uid>/`)
- Auth middleware: validates `_pwd_sess` JWE cookie; CSRF middleware enforces `X-CSRF-Token` header on all state-changing methods
- Password hashing: scrypt (N=2¹⁷, r=8, p=1). The browser-side `src/utils/crypto.ts` uses PBKDF2 — that is only for daemon/localStorage paths
- Sessions: JWE tokens (`A256GCM`, 24h TTL), active JTIs tracked per-user for invalidation

**`src/utils/daemonClient.ts`**: `DaemonClient` class wraps the WebSocket proxy. Serialises requests one-at-a-time (FIFO queue). `daemon` is a module-level singleton. All vault commands are typed methods on this class.

**`src/crypto/keystore.ts`**: `SecureKeyStore` holds the daemon session token in a JS private field. `clear()` is called on logout, on session expiry, and after a 5-minute grace period of the tab being hidden (`visibilitychange → hidden` starts a timer; becoming visible again or `pagehide` cancels it — this avoids clearing on an ordinary page refresh while still bounding how long keys survive in a backgrounded tab). Also stores a per-session `CryptoKey` for local config encryption.

**State management**: Three React context providers defined in `src/main.tsx` — `VaultContext`, `NotificationContext`, `ThemeContext`. `UserContext` is nested inside `AppLayout` (not `main.tsx`) so it re-mounts on login/logout.

**Auth flow**:
- Daemon available → `Login.tsx` calls `daemon.unlock(password)` → session token stored in `SecureKeyStore`
- Server session → `Login.tsx` calls `POST /api/auth/login` → `_pwd_sess` + `_pwd_csrf` cookies set; `VaultContext.hasServerSession()` returns true
- `AppLayout.tsx` guards authenticated routes; redirects to `/login` when `keyStore.hasToken` is false

**Security modes** (`src/utils/securityModes.ts`):
- **Duress mode**: alternate password triggers forensic wipe after N failed attempts
- **Travel mode**: encrypts a subset of credentials with a travel password, hiding them from the main vault
- **Forensic wipe**: 7-pass overwrite via daemon (vault.db) + 3-pass browser wipe of localStorage/IndexedDB/caches

**Patterns**:
- `@/` path alias maps to the `web/` project root (Vite + TypeScript)
- All user-facing strings use `useTranslation()` (i18next); translation files: `src/locales/en.json` and `src/locales/fr.json`
- Never use `localStorage.getItem/setItem` directly for vault data; use `readDecryptedLocal` / `writeEncryptedLocal` from `src/utils/localCrypto.ts` (XChaCha20-Poly1305 via `@noble/ciphers`)
- Folder icon custom SVGs stored in `Folder.customSvg` must go through DOMPurify before rendering

---

## IPC Protocol

The canonical source is `daemon/src/ipc/protocol.rs`. When adding a new daemon command:
1. Add variants to `Request` and `Response` enums in `protocol.rs`
2. Add a match arm in `dispatch()` in `socket.rs`
3. Add a typed method on `DaemonClient` in `daemonClient.ts`

All authenticated requests include `session_token: string` in the payload. The daemon validates UID + token in `auth_then!` before touching the DB.

---

## Cryptographic Boundaries

- **Never** put key material (KEK, VMK, DEK) into React state, localStorage, sessionStorage, or IndexedDB.
- `SecureKeyStore` (`web/src/crypto/keystore.ts`) holds the session token in a JS private field; `clear()` is called on logout, session expiry, and after a 5-minute grace period of the tab being backgrounded (not on refresh — see keystore.ts for the timer logic).
- All credential encryption/decryption runs inside the daemon. The browser receives only opaque JSON blobs (credentials) from daemon responses.
- OTP codes for credentials are generated by the daemon (`GetOtpCode`), not the browser.
- Server-side user data lives in `auth_data/` as AES-256-GCM encrypted files (HKDF-derived keys from a per-installation master key in `auth_data/.master_key`).

---

## Deploy

Nginx (`deploy/nginx/vault.conf`) proxies HTTPS → Express:3000. It handles TLS termination, HSTS, rate limiting, and static asset caching. The Express server injects the per-request CSP nonce; Nginx must not set its own `Content-Security-Policy` header to avoid duplicates.

systemd unit (`deploy/vault-daemon.service`) runs the daemon as user `vault` with `MemorySwapMax=0`, `NoNewPrivileges`, `PrivateTmp`, and `CAP_IPC_LOCK` for mlock.

AppArmor profile (`deploy/apparmor.d/vault-daemon`) currently has library paths hard-coded to `aarch64-linux-gnu`. Update for `x86_64-linux-gnu` when deploying on x86 hosts.

---

## VaultHeader Sidecar (`.meta` file)

`DaemonState` stores two files side-by-side: `vault.db` (SQLCipher) and `vault.db.meta` (plaintext JSON `VaultHeader`). The sidecar is the **only** file the daemon reads before the vault is unlocked, so it contains everything the login page needs:

| Field | Purpose |
|---|---|
| `vault_uuid` / `argon2_salt` | Key derivation inputs |
| `encrypted_vmk` / `vmk_nonce` | KEK-wrapped VMK (XChaCha20-Poly1305) |
| `password_login_enabled` | `false` = hide password field at login |
| `totp_enabled` / `email_otp_enabled` | Which MFA methods are required |
| `passkey_credentials` | Per-passkey encrypted VMK copies (Option B passwordless) |
| `wipe_ticket` | 32-byte hex capability token authorising `ForensicWipe` |

The sidecar is written by `DaemonState::write_header()` in `daemon/src/vault/state.rs`. The unauthenticated `GetLoginHints` IPC command reads it and returns a `Response::LoginHints` — this is the **authoritative** source for the frontend login policy.

Changing master password clears `passkey_credentials` (they wrapped the old VMK); users must re-register passkeys after a password change.

---

## MFA Config Architecture (frontend)

`web/src/utils/mfa.ts` maintains two storage layers for the `MfaConfig` object:

1. **In-memory cache** (`_mfaCache`) — the live working copy; synchronous reads via `getMfaConfig()`.
2. **localStorage** — two keys written on every `saveMfaConfig()` call:
   - `mfa_config` (AES-GCM encrypted when local key is in memory; plaintext otherwise)
   - `mfa_config_plain` (plaintext backup — survives page refreshes after the in-memory key is cleared)

`saveMfaConfig()` also calls `daemon.updateLoginPolicy()` to sync `password_login_enabled`, `totp_enabled`, `email_otp_enabled` to the sidecar. **The daemon sidecar is the source of truth at login time**; the localStorage cache is for the authenticated session UI only.

Call `clearMfaCache()` on logout to prevent the next user on the same device from seeing a previous account's config.

---

## Passkey / Security Key Login Flow

The correct end-to-end passwordless unlock sequence:

1. `daemon.getLoginHints()` → `{ fido2_ids, password_login_enabled, ... }` (reads sidecar, no vault open needed)
2. `daemon.getPasskeyChallenge()` → 32-byte random challenge (stored server-side, consumed once)
3. `navigator.credentials.get(...)` with the returned challenge and `allowCredentials` from step 1
4. `daemon.unlockWithPasskey(credentialId, authData, signature)` → derives VMK wrap key from `auth_data[0..33]` + `credential_id`, decrypts VMK copy from sidecar, opens DB, issues session token

This flow is implemented in `authenticateWebAuthnForLogin()` in `mfa.ts`.

---

## Brute-Force Lockout (H-01)

`DaemonState` applies exponential back-off after repeated failed unlock attempts. The schedule (`LOCKOUT_SCHEDULE_SECS` in `state.rs`) locks out for 30 s after the 5th failure, 60 s after the 6th, up to 600 s. The counter resets to zero on any successful unlock.

---

## DaemonClient Request Model

Requests are serialised FIFO — only one in-flight at a time per `DaemonClient` instance. On **timeout**, the entire WebSocket is torn down (not just the pending request) because responses are matched by position; removing a mid-queue entry would misalign all subsequent responses. After a timeout the caller must reconnect before issuing new requests.

Error responses from the daemon are sanitised in `daemonClient.ts` (`SAFE_MESSAGES` map) — internal codes like `InvalidPassword` become generic UI strings so implementation details are not leaked to the browser (MED-06).

---

## E2E Tests (Playwright)

Playwright config is at `web/playwright.config.ts`; tests live in `web/e2e/`.

```bash
cd web && npx playwright test                                          # run all E2E tests
cd web && npx playwright test e2e/comprehensive-platform.spec.ts      # Full platform regression test
cd web && npx playwright test --headed                                 # run with browser visible
```

**`e2e/comprehensive-platform.spec.ts`** is the gold-standard regression gate. It walks through auth (success/failure), navigation, i18n, folder/asset CRUD, Duress Mode, and account destruction. Run it before shipping any frontend or auth-related change.

---

## Runtime Data Directory

During development the daemon stores `vault.db` and `vault.db.meta` in `daemon_data/` at the project root. This directory is created automatically on first unlock. It is not committed; delete it to reset to a fresh vault state.

---

## graphify

The web project has a graphify knowledge graph at `web/graphify-out/`. Before answering architecture or codebase questions, check `web/graphify-out/GRAPH_REPORT.md` for god nodes and community structure. After modifying code files, run `graphify update .` from `web/` to keep the graph current.


<default_to_action>
By default, implement changes rather than only suggesting them. If the user's intent is unclear, infer the most useful likely action and proceed, using tools to discover any missing details instead of guessing. Try to infer the user's intent about whether a tool call (e.g., file edit or read) is intended or not, and act accordingly. 
</default_to_action>
<use_parallel_tool_calls>
If you intend to call multiple tools and there are no dependencies between the tool calls, make all of the independent tool calls in parallel. Prioritize calling tools simultaneously whenever the actions can be done in parallel rather than sequentially. For example, when reading 3 files, run 3 tool calls in parallel to read all 3 files into context at the same time. Maximize use of parallel tool calls where possible to increase speed and efficiency.
However, if some tool calls depend on previous calls to inform dependent values like the parameters, do NOT call these tools in parallel and instead call them sequentially. Never use placeholders or guess missing parameters in tool calls. 
</use_parallel_tool_calls>
