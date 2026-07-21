# Browser Extension (Chrome/Edge/Firefox) — Design Spec

**Date:** 2026-07-21
**Status:** Approved
**Depends on:** `2026-07-20-extension-and-selfhost-vault-design.md` (server-mode backend, `SelfHostKmsProvider`)
**Code location:** `~/Documents/PWDnow_extension` — a **separate repository**, NOT inside `PWDnow/`. Per explicit instruction, no extension code lives in this repo. This spec lives here only because it documents integration points with the server described in this repo.

## 1. Goal

A Chrome/Edge/Firefox extension (v1) that, against a running PWDnow **server-mode** instance:
- Lets the user log in with their PWDnow email + master password.
- Lists credentials matching the domain of the active tab.
- Fills a matched credential's username/password into the active tab's form.
- Generates a new password (same algorithm as the web app) and saves it as a new credential.

Out of scope for v1 (explicitly deferred): daemon-mode/local-only support, OAuth-style device-grant pairing, folder creation from the extension, in-page overlay icons (only a toolbar popup), MFA methods beyond what's needed to not break login (see §4), and any change to the PWDnow repo itself.

## 2. Why not reuse the browser's session cookie?

Initially assumed a zero-backend-change approach (extension reads/reuses the existing `_pwd_sess` session cookie). Ruled out after grounding in the actual code:

- `_pwd_sess` is `SameSite=Strict` and there is no CORS configuration on `/api/vault/*` or `/api/auth/*` — an extension background-worker `fetch()` would not reliably send the cookie, and even if it did, the response would be unreadable cross-origin.
- More fundamentally, vault data is end-to-end encrypted client-side. The decryption key lives only as a private JS field inside `SecureKeyStore` in the web app's own execution context — not reachable by a content script (isolated world) or a background worker.

**Resolution:** the extension has to (a) talk to the server as if it *were* a same-origin client, and (b) independently derive the same encryption key from the master password. Both are solved below.

## 3. Architecture

**Framework:** WXT (TypeScript, Manifest V3, single codebase → Chrome, Edge, Firefox).

**Components:**
- **Popup (React)** — the only UI surface in v1. Connect screen, credential list for the active tab's domain, Fill/Generate/Save actions.
- **Background service worker** — orchestrates login, key derivation, vault fetch/decrypt, session-key caching. Owns the "relay" mechanism (§4).
- **Relay content script** — injected via `chrome.scripting.executeScript` into a tab of the configured PWDnow origin. Its only job is issuing `fetch()` calls to `/api/auth/*` and `/api/vault/*` from *inside* that origin's own JS context, so cookies/CSRF behave exactly as they do for the real web app. It has no UI and touches no page DOM.
- **Fill content script** — injected on demand into the *active* tab (whatever site the user is on) to read/write form fields.

## 4. Auth & key derivation (exact port of the server-mode crypto)

Verified directly from `web/src/crypto/keystore.ts` and `web/src/utils/localCrypto.ts`:

- Server-mode vault blobs are encrypted with a **v1 key**: `PBKDF2-SHA-512(password, cryptoSalt, 600,000 iterations, 64-byte output)`, first 32 bytes used as an AES-256-GCM key. (The v2 Argon2id key is session-token-bound and irrelevant here — server blobs are always v1.)
- Blob format (`encryptForServer`/`decryptFromServer`): `BASE64URL(12-byte IV ‖ AES-GCM ciphertext+tag)`. No outer HMAC layer (that's only the separate `writeEncryptedLocal` v2 local-storage format, not used for server blobs).
- `cryptoSalt` is server-authoritative, delivered via the `X-Vault-Salt` response header:
  - `POST /api/auth/login` `{email, password}` → on full success, `{ok:true}` + `X-Vault-Salt` header (32-char hex).
  - If MFA is required: `{ok:true, partialToken, methods:[...]}`, **no** `X-Vault-Salt` yet.
  - Invalid creds: `{ok:false, error:'invalid_credentials'|'account_locked'|'too_many_requests'}`.
  - Hardware-key-only accounts: `403 hardware_mfa_requires_daemon` — the extension cannot support these in v1; show an explicit "not supported" message rather than a generic failure.
- For a session where the extension already holds a valid `_pwd_sess` cookie but has lost its derived key (e.g., popup reopened after the service worker was evicted), it calls `POST /api/auth/crypto-salt` to re-fetch the salt without a full re-login. The password is still required at that point to re-derive the key (the extension never persists the password).

**v1 login flow:**
1. User enters server URL, email, master password in the Connect screen.
2. Background asks for `host_permissions` on that origin via `chrome.permissions.request` (one-time).
3. Relay content script POSTs `/api/auth/login`.
4. If `methods` comes back (TOTP/email OTP required), popup shows a code-entry field and relay POSTs `/login/finish` with the code + `partialToken`. (Hardware-key-only → show unsupported message, stop.)
5. On full success, background captures `X-Vault-Salt`, derives the AES key, fetches + decrypts `/api/vault/credentials` and `/api/vault/folders`.

**Storage tiers:**
- `chrome.storage.local` (non-secret): server URL, email.
- `chrome.storage.session` (cleared on browser close): the derived AES-GCM key, exported as raw bytes.
- Nowhere: the master password itself — used transiently in memory during derivation, never written to any storage.

## 5. Networking via relay content script

All HTTP calls (login, `/login/finish`, `/api/auth/crypto-salt`, `/api/vault/credentials` GET/PUT, `/api/vault/folders` GET/PUT) are executed by a function injected into a tab of the configured PWDnow origin via `chrome.scripting.executeScript`, using `fetch(..., {credentials: 'include'})` from inside that tab's own context. This makes every request genuinely same-origin — real cookies, real `_pwd_csrf` reads, no CORS involved, no server change needed. The background service worker opens/reuses a background tab of that origin (created hidden/pinned) to host these calls; it does not depend on the user actively browsing the PWDnow site.

## 6. Data model & sync (whole-blob replace)

`/api/vault/credentials` and `/api/vault/folders` are GET/PUT whole-blob endpoints (`{data: "<encrypted-blob>"}`), matching `VaultContext.tsx`'s own pattern — there is no per-item endpoint. The extension:
- Decrypts the full array on fetch.
- For **Save**: appends a new credential (`crypto.randomUUID()` for `id`), defaulting `folderId` to the first folder returned by `/api/vault/folders` (creating folders from the extension is out of scope for v1 — if the vault has zero folders, show a "create a folder in the web app first" message).
- Re-encrypts the full array and PUTs it back with the CSRF header.
- Conflict handling: last-write-wins. Acceptable for v1 given this is a single-user-driven action (save is rare, and a stale overwrite would only lose credentials added from *another* device in the same few-second window).

## 7. Core UX (toolbar popup only)

- **Match view**: popup lists credentials whose `url` hostname matches `chrome.tabs.query({active:true}).url` hostname.
- **Fill**: `chrome.scripting.executeScript` into the active tab; best-effort field detection (common selectors for username/email and password inputs), sets `.value` and dispatches `input`/`change` events so frameworks pick up the change.
- **Generate**: local port of the web app's `PasswordGenerator` logic — character-set mode (length 8–64, default 24, full charset) and passphrase mode (EFF wordlist, 3–10 words default 6), both using `crypto.getRandomValues` with rejection sampling to avoid modulo bias.
- **Save**: reads the active tab's current form field values (via the fill content script), builds a new credential object, runs the append-and-PUT flow from §6.

## 8. Error handling

- Network/relay failures (background tab not reachable, origin unreachable) surface as a popup banner, not a silent failure.
- Login failures show the server's actual category (`invalid_credentials`, `account_locked`, `too_many_requests`, `mfa_locked`) mapped to plain-language popup text — no raw error codes shown to the user.
- Decrypt failures (wrong key, corrupted blob) are treated as "wrong password" and prompt re-entry — never surfaced as a crash.

## 9. Testing

Given this is a new, separate repo: unit tests (Vitest, matching the web project's own tooling choice) for the KDF port, blob encrypt/decrypt round-trip, and the password generator, plus a manual end-to-end checklist (connect, MFA login, fill, generate, save, re-open popup after service-worker eviction) since full browser-extension E2E harnessing is disproportionate for a v1 slice.

## 10. Explicitly deferred

- Local/daemon-mode support.
- OAuth-style device-grant pairing (`device_grants` backend, daemon `IssueExtensionGrant` IPC) — per the earlier "harden later" decision in the parent spec.
- In-page overlay/autofill icons.
- Folder creation from the extension.
- Wiring `KMS_PROVIDER=selfhost` into `install.sh`.
