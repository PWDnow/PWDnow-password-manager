# Extension Vault Access + Self-Host (Pi 5) Database Design

**Status:** Approved 2026-07-20. Builds directly on the approved SaaS scalability design
(`docs/superpowers/specs/2026-06-07-saas-scalability-design.md`, Model C) and its P1
implementation (Postgres + per-user envelope encryption + pluggable KMS), already coded on
this branch (`saas-p1-postgres-envelope-kms`).

**Goal:** Define how the database/backend layer must work so that:
1. A Chrome/Edge/Firefox extension can autofill logins, generate + save new credentials on
   account-creation forms, for any deployment.
2. Self-hosters (e.g. a Raspberry Pi 5) can run one instance for family/friends, each with
   their own account, accessed from phone/laptop/etc.
3. Pure local single-user installs (Windows/Mac/Linux) keep working exactly as today.

Crypto posture stays CNSA 2.0 / NIST PQC L5 throughout — no primitive is weakened anywhere in
this design. The Rust daemon remains single-tenant; this design does not make it multi-tenant.

---

## 1. Deployment / client matrix

| Deployment | Backend | Auth | New work |
|---|---|---|---|
| Local-only (single user, own machine) | Rust daemon, SQLCipher, single-tenant | `daemon.unlock()` → session token in browser | New extension-grant IPC capability (§4) |
| Self-hosted family/friends (Pi 5) | Express server-mode, Postgres (P1), per-user envelope DEK | JWE cookie (`_pwd_sess`) | Finish P1 cutover; new `SelfHostKms` (§3) |
| Cloud/K8s SaaS (100k+ users) | Same Postgres path, Vault Transit or cloud KMS | Same | Unchanged — already scoped in P2/P3 |

The daemon staying single-tenant/unchanged for scaling purposes is not revisited here. Adding
an extension-pairing capability to it is a new feature orthogonal to that decision, not a
reopening of it.

## 2. Local-only mode — no material change

SQLCipher, per-item DEKs, 15-minute idle session expiry, and brute-force lockout are all
untouched. The only new surface it picks up is the extension-grant IPC capability (§4).

## 3. Self-hosted server mode — finish the P1 cutover, add `SelfHostKms`

**a) Finish the already-built P1 cutover first.** Per the P1 plan doc's "Next step": browser
E2E on a restarted dev instance, then merge. Extension work should not be built on top of an
unmerged data layer.

**b) `SelfHostKms`** — a third `KmsProvider` implementation alongside the existing
`LocalDevKmsProvider` (dev/CI only, explicitly unsafe for prod) and `VaultTransitKmsProvider`.
Same `wrapDek`/`unwrapDek` contract, so it drops into the existing envelope/Postgres machinery
with no changes elsewhere. Hardening over `LocalDevKmsProvider`:
- Master key file must be `0600`, owner-checked at startup; refuse to boot if group/world-readable.
- Optional passphrase-wrapped-at-rest mode (admin sets a passphrase during install; the master
  key is wrapped, unwrapped into memory once at process start).

This becomes the installer's default KMS choice for a "self-host, small scale" profile.
Vault Transit remains available for anyone who wants it regardless of scale.

## 4. Extension token model — rotating access/refresh grant, tiered storage

The extension is architecturally "just another frontend": it must obey the same
zero-knowledge / no-key-persistence rules as the SPA, but it cannot use `_pwd_sess`/`_pwd_csrf`
cookies (no shared cookie jar across origins) and must not reach into `SecureKeyStore`'s
private field (that boundary stays intact).

**Pairing (same UX regardless of backend):**
1. User opens Settings → "Connect Browser Extension" in the already-unlocked web app →
   server/daemon issues a short-lived (~2 min) one-time pairing code (digits or QR).
2. Extension exchanges the code for a device grant: a **refresh token** (opaque ≥256-bit
   random; only its HMAC hash is ever persisted — same blind-index technique as `email_hmac`)
   plus scope list (e.g. `vault:read:credentials`, `vault:write:credentials` — never a full
   session-equivalent grant) and device label.
3. Extension immediately receives a short-lived **access token** (15-minute TTL) and uses it
   as `Authorization: Bearer …` on every vault call. CSRF does not apply to this path — nothing
   here is ambient-credential-based.
4. Before expiry, the extension silently exchanges the refresh token for a new access token.
   **Refresh tokens rotate on every use**; reuse of an already-rotated refresh token is treated
   as a theft signal — the whole device grant is auto-revoked and a high-severity audit event
   is logged (visible in the existing Sessions UI).
5. Devices are revocable from the same Settings screen — a device grant becomes another row
   alongside login sessions.

**Extension-side storage tiering:**
- Access token: in-memory / `chrome.storage.session` only.
- Refresh token, default: `chrome.storage.session` (cleared on browser close → quick re-pair).
- Refresh token, opt-in "keep me connected on this device": encrypted with a key derived via
  Argon2id from a short **Extension PIN** (separate from the vault master password), stored in
  `chrome.storage.local`. No OS keychain, no native-messaging host — that per-browser/per-OS
  infra isn't worth building given loopback HTTP + our own KDF already give strong, bounded
  guarantees, and rotation-reuse detection bounds the blast radius of a stolen persistent token.

**Platform additions required:**
1. Server-mode: `device_grants` table (refresh-token hashes, scope, label, timestamps) on the
   `VaultRepository` interface (both `FileVaultRepository` and `PostgresVaultRepository`, same
   pattern as P1.A's row-oriented user methods) + an ephemeral access-token store (reuses the
   P0 `StateStore` abstraction — this is exactly what it was built for).
2. New pairing-code issue/exchange, refresh (with rotation-reuse detection), and revoke
   endpoints.
3. Daemon: new `IssueExtensionGrant` / `RefreshExtensionGrant` / `RevokeExtensionGrant` IPC
   commands + a new encrypted table in `vault.db` for refresh-token hashes.
4. UI: "Connect Extension" pairing screen in Settings (extends the existing Sessions list) +
   PIN-unlock in the extension popup.

## 5. Data model for autofill — no schema change

`Credential.url` (a plain string, `web/src/types.ts`) is sufficient for v1. The extension
fetches the same whole decrypted `credentials` resource the SPA already fetches (KBs, not
rows) via its device-grant token, and matches by domain **client-side in the service worker**
— no new server-side filtering logic, no schema change. "Generate + save on account creation"
reuses the existing `setResource` write path unchanged.

Deferred (not blocking, noted for later if the need actually arises):
- Multi-URI-per-credential matching with match-type (domain/host/exact/never), Bitwarden-style.
- Per-credential row normalization (already flagged as deferred in the P1 plan) — extension
  write frequency at family/individual scale doesn't change that calculus.

## 6. Family sharing — confirmed model

Each family/friend gets their own separate account on the one shared Pi-5 server instance —
this is Postgres's native per-user shape already. Ad hoc sharing of individual credentials
between accounts uses the existing `ShareModal`/`ShareView` one-time-link feature as-is. No new
schema.

## 7. Rollout order

1. **Finish P1** — merge already-built Postgres/envelope/KMS work (prerequisite for everything below).
2. **`SelfHostKms`** — new `KmsProvider` adapter + installer "small self-host" default.
3. **P-Ext-A (server-mode)** — `device_grants` schema + `StateStore`-backed access-token cache
   + pairing/refresh/revoke endpoints + Sessions UI extension.
4. **P-Ext-B (daemon)** — matching `IssueExtensionGrant`/`RefreshExtensionGrant`/`RevokeExtensionGrant`
   IPC + new encrypted table in `vault.db`, for local-only mode.
5. **P-Ext-C (extension itself)** — separate project at `~/Documents/PWDnow_extension` (kept out
   of this repo per explicit instruction); depends on P-Ext-A/B's APIs existing.
6. P2/P3 (Redis everywhere, K8s) — unchanged, independent track from prior roadmap.

---

## Non-goals / explicitly out of scope

- Native messaging host / OS keychain integration for the extension (see §4 rationale).
- Making the Rust daemon multi-tenant.
- Shared/pooled family vault (one login for everyone) — rejected in favor of §6.
- Any weakening of AES-256-GCM / Argon2id / HKDF-SHA384 / HMAC-SHA256 parameters.
