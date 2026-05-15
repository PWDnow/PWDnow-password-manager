# PWDnow — Feature Build Progress Tracker
> **Purpose:** Checkpoint file. If the session is interrupted (server restart, connection drop), resume here — do not start from scratch. Read this file + `FEATURE_PLANNING.md` before any code change.
> **Last updated:** 2026-04-30

---

## Status Legend
- `[ ]` Not started
- `[~]` In progress (notes the partial state)
- `[x]` Complete
- `[!]` Blocked (reason noted)

---

## Phase 1-A: Feature 5 — IP-Enriched Audit Log + Threat Blocking

### Sub-task 5.1 — New file: `web/ipIntelligence.js`
- [x] Create `IpIntelligenceService` class
  - [ ] Constructor: accepts `apiKey` (from `process.env.IPREGISTRY_API_KEY`)
  - [ ] `lookup(ip)` method
    - [ ] Short-circuit for loopback/private ranges: `127.*`, `::1`, `10.*`, `172.16-31.*`, `192.168.*`, `fc00::/7`
    - [ ] Short-circuit if `apiKey` is empty/null → return null (no-op mode)
    - [ ] In-memory LRU cache: max 500 entries, 1-hour TTL (use a `Map` + timestamp; evict on access)
    - [ ] Request deduplicator: if same IP is being looked up, return the same in-flight Promise
    - [ ] `GET https://api.ipregistry.co/{ip}?key={apiKey}&fields=security,location,connection,type,hostname`
    - [ ] Handle 429 → fail open (return null, log warning to stderr)
    - [ ] Handle network error → return null (never throw to callers)
    - [ ] Normalize response to `IpRecord` shape: `{ ip, country, countryCode, countryFlag, city, region, org, connectionType, hostname, isTor, isProxy, isVpn, isAbuser, isAttacker, isCloudProvider, riskFlags }`
  - [ ] `isThreat(record, policy)` method — returns boolean based on policy toggles
  - [ ] `getRiskFlags(record)` — returns `string[]` like `['tor', 'vpn']`
  - [ ] `module.exports = { IpIntelligenceService }`

### Sub-task 5.2 — `web/.env.example` update
- [ ] Add line: `IPREGISTRY_API_KEY=` (empty, with comment: "Get your key at ipregistry.co — leave empty to disable IP threat detection")

### Sub-task 5.3 — IP blocking middleware in `web/auth.js`
- [ ] Import `IpIntelligenceService` at top of `auth.js`
- [ ] Instantiate: `const ipIntel = new IpIntelligenceService(process.env.IPREGISTRY_API_KEY ?? '')`
- [ ] Load server-level policy from `auth_data/.ip_policy.json` on startup (defaults: blockTor=true, blockProxy=true, blockVpn=false, blockAbuser=true)
- [ ] Add `blockingMiddleware` async function: runs before `mountAuthAndVault` routes
  - [ ] Get client IP via `getClientIp(req)`
  - [ ] Call `ipIntel.lookup(ip)` — await
  - [ ] If record is null → `next()` (no key, private IP, or API error)
  - [ ] If `ipIntel.isThreat(record, policy)` → 
    - [ ] Log blocked event to server-wide `auth_data/blocked_ips.log` (append-only plaintext, not per-user)
    - [ ] Return `res.status(403).json({ error: 'access_denied' })` — generic, no detail
  - [ ] Attach `req.ipRecord = record` for audit logging downstream
  - [ ] `next()`
- [ ] Mount `blockingMiddleware` on `app.use()` before any auth routes

### Sub-task 5.4 — Audit event log infrastructure in `web/auth.js`
- [ ] Add `auditLogPath(uid)` → `path.join(DATA_DIR, 'vault', uid, 'audit_log.enc')`
- [ ] Add `userInfo` key context for audit log: `userInfo(uid, 'audit_log')`
- [ ] `loadAuditLog(uid)` — `readEncryptedFile(auditLogPath(uid), ..., [])`
- [ ] `saveAuditLog(uid, events)` — `writeEncryptedFile(...)`, max 1000 entries FIFO
- [ ] `appendAuditEvent(uid, event)` — load, push, save
- [ ] `AuditEvent` structure (JS object):
  ```js
  {
    id: randomUUID(),
    ts: Date.now(),
    action: string,    // see AuditAction list in FEATURE_PLANNING.md
    ip: string,        // full IP, encrypted at rest
    ipInfo: object,    // compact: { country, countryCode, countryFlag, city, org, connectionType, riskFlags }
                       // only store if riskFlags.length > 0, else null
    userAgent: string,
    resourceId: string | null,
    resourceLabel: string | null,
    success: boolean,
    riskFlags: string[],
    detail: string | null
  }
  ```
- [ ] Hook audit events into existing handlers:
  - [ ] Login success (`/api/auth/login` — after session issued) → action `'login'`
  - [ ] Login failed (wrong password) → action `'login_failed'`
  - [ ] Logout (`/api/auth/logout`) → action `'logout'`
  - [ ] Credential create (`POST /api/vault/credentials`) → `'credential_created'`
  - [ ] Credential update (`PUT /api/vault/credentials/:id`) → `'credential_updated'`
  - [ ] Credential delete (`DELETE /api/vault/credentials/:id`) → `'credential_deleted'`
  - [ ] Share create (`POST /api/vault/shares`) → `'share_created'`
  - [ ] Share revoke (`DELETE /api/vault/shares/:id`) → `'share_revoked'`
  - [ ] Password change (`PUT /api/auth/password`) → `'password_changed'`
  - [ ] MFA change (any MFA update route) → `'mfa_changed'`
  - [ ] NOTE: `credential_read` events ONLY recorded when `req.ipRecord?.riskFlags.length > 0`
- [ ] Add API routes:
  - [ ] `GET /api/audit/events` — auth required, supports `?limit=50&offset=0&action=&since=`
  - [ ] `DELETE /api/audit/events` — auth + CSRF required, clears user's log

### Sub-task 5.5 — Settings UI upgrades (`web/src/pages/Settings.tsx`)
- [ ] New card: "IP Threat Protection"
  - [ ] ipregistry API key input field (password type, toggle reveal)
  - [ ] "Save" button → `PUT /api/auth/profile` with `{ ipregistryKey }` or a dedicated settings endpoint
  - [ ] Status indicator: "Active" (green) / "Not configured" (gray)
  - [ ] Policy toggles (read from server, stored in user profile):
    - [ ] Block Tor / Anonymous Networks [default ON]
    - [ ] Block Known Proxies [default ON]
    - [ ] Block VPN Exits [default OFF] + disclaimer
    - [ ] Block Abusive & Attacking IPs [default ON]
- [ ] Upgrade existing Audit Log modal:
  - [ ] Tabs: All | Logins | Credentials | Security
  - [ ] Table columns: Time | Action | Location | Network | Risk | Resource | Status
  - [ ] Risk badge: green / yellow / red based on `riskFlags`
  - [ ] Row expand → full IP (masked `*.*.*.**` default, reveal button)
  - [ ] `useEffect` loads from `GET /api/audit/events`
  - [ ] Pagination: "Load more" button
  - [ ] "Clear Log" button → confirm dialog → `DELETE /api/audit/events`
  - [ ] Augment "Export CSV" with new audit fields
- [ ] i18n: add all new strings to `en.json` + `fr.json`

---

## Phase 1-B: Feature 3 — Active Share Links in Settings

### Sub-task 3.1 — Backend: store `label` in share record (`web/auth.js`)
- [ ] `POST /api/vault/shares` — accept `label` in request body, save to share JSON file

### Sub-task 3.2 — `web/src/components/ShareModal.tsx`
- [ ] Include `label: credential.service` in POST body

### Sub-task 3.3 — Settings UI (`web/src/pages/Settings.tsx`)
- [ ] New card: "Active Share Links" (place after Audit Log card)
  - [ ] `useEffect` on mount → `GET /api/vault/shares`
  - [ ] Empty state: "No active share links"
  - [ ] Table: Service name | Created | Expires | View-once | Viewed | [Revoke]
  - [ ] "Revoke All" button → iterate shares, call `DELETE /api/vault/shares/:id` for each
  - [ ] Individual revoke button → `DELETE /api/vault/shares/:id` with CSRF header
  - [ ] After revoke → re-fetch list
- [ ] i18n: add new strings to `en.json` + `fr.json`

---

## Phase 1-C: Feature 10 — PWA

### Sub-task 10.1 — Install dependency
- [ ] `npm install -D vite-plugin-pwa` in `web/`
- [ ] Verify `package.json` updated

### Sub-task 10.2 — App icons
- [ ] Create `web/public/icons/` directory
- [ ] Generate `icon-192.png` (192×192)
- [ ] Generate `icon-512.png` (512×512)
- [ ] Generate `icon-512-maskable.png` (512×512, safe-zone padding for maskable)
- [ ] Favicon already exists? Verify at `web/public/favicon.ico`

### Sub-task 10.3 — `web/public/manifest.json` (new file)
- [ ] Create with fields: name, short_name, description, start_url, display, orientation, background_color, theme_color, scope, icons

### Sub-task 10.4 — `web/vite.config.ts` changes
- [ ] Import `VitePWA` from `vite-plugin-pwa`
- [ ] Add to plugins array with Workbox config:
  - [ ] `registerType: 'autoUpdate'`
  - [ ] `manifest: false` (use `public/manifest.json`)
  - [ ] `workbox.globPatterns` for JS/CSS/HTML/PNG/SVG/woff2
  - [ ] `workbox.navigateFallback: '/'`
  - [ ] `workbox.navigateFallbackDenylist: [/^\/api\//, /^\/ws/, /^\/share\//]`
  - [ ] `workbox.runtimeCaching` for `/locales/` (CacheFirst, 24h TTL)
  - [ ] `workbox.cleanupOutdatedCaches: true`

### Sub-task 10.5 — `Cache-Control` headers on auth routes (`web/auth.js` / `web/server.js`)
- [ ] Add `res.setHeader('Cache-Control', 'no-store')` to all `/api/auth/**` responses
- [ ] Verify `/api/vault/**` responses also have `no-store`

### Sub-task 10.6 — `InstallPrompt` component (`web/src/components/InstallPrompt.tsx`, new file)
- [ ] Listen for `beforeinstallprompt` event, store `deferredPrompt`
- [ ] Show install banner only when: `deferredPrompt` is set AND user is authenticated (not on login/register/setup)
- [ ] "Install" button → call `deferredPrompt.prompt()`, await `userChoice`
- [ ] "Dismiss" button → set `localStorage.setItem('pwa_install_dismissed', '1')`, hide
- [ ] On mount: if `localStorage.getItem('pwa_install_dismissed')` is set → don't show
- [ ] Detect `window.matchMedia('(display-mode: standalone)').matches` → if already installed, don't show

### Sub-task 10.7 — Mount InstallPrompt in layout
- [ ] `web/src/layouts/AppLayout.tsx` → import and render `<InstallPrompt />`

### Sub-task 10.8 — NetworkStatus upgrade (`web/src/components/NetworkStatus.tsx`)
- [ ] Detect server mode vs daemon/local mode via `VaultContext.hasServerSession()`
- [ ] Offline + server mode: "You're offline. Vault is unavailable until you reconnect."
- [ ] Offline + daemon mode: "You're offline. Your vault is available in read-only mode."
- [ ] i18n: add strings to `en.json` + `fr.json`

---

## Phase 2: Features 4 + 7 — Credential Types (Login / Passkey / Secure Note / Payment Card)

### Sub-task 4+7.1 — Type system (`web/src/types.ts`)
- [ ] Add `CredentialType = 'login' | 'passkey' | 'secure_note' | 'payment_card'`
- [ ] Add optional fields to `Credential`:
  - [ ] `credentialType?: CredentialType` (undefined = 'login')
  - [ ] Passkey fields: `rpId`, `rpName`, `credentialId`, `userHandle`, `authenticatorName`, `backedUp`
  - [ ] Secure note fields: `noteContent`
  - [ ] Payment card fields: `cardholderName`, `cardNumber`, `cardExpiry`, `cardCvv`, `cardBillingAddress`, `cardType`

### Sub-task 4+7.2 — AddCredential form (`web/src/pages/AddCredential.tsx`)
- [ ] Add state: `credentialType: CredentialType` (default `'login'`)
- [ ] Type selector UI: 4 option cards at top of form with icons
  - [ ] Login (key icon) — default
  - [ ] Passkey (fingerprint / shield icon)
  - [ ] Secure Note (document / file-text icon)
  - [ ] Payment Card (credit-card icon)
- [ ] Conditional sections:
  - [ ] `credentialType === 'login'` → existing form (unchanged)
  - [ ] `credentialType === 'passkey'` → rpId, rpName, username/display name, credentialId, userHandle, authenticatorName, backedUp toggle, notes. Add tooltip: "Private key stays on your authenticator — we never store it here."
  - [ ] `credentialType === 'secure_note'` → title only + large noteContent textarea. Max 50KB client-side check.
  - [ ] `credentialType === 'payment_card'` → cardholderName, cardNumber (masked), cardExpiry, cardCvv (masked), cardBillingAddress, notes. Add PCI disclaimer text.
- [ ] Card number input: use `secureClipboard()` on copy, show last 4 only by default with reveal toggle
- [ ] CVV input: masked by default, same reveal toggle pattern as passwords
- [ ] Card type detection (Visa/MC/Amex/Discover) → sets `cardType` cosmetically
- [ ] Include `credentialType` in the saved credential object

### Sub-task 4+7.3 — Vault list display (`web/src/pages/Vault.tsx`)
- [ ] Credential card variants based on `credentialType`:
  - [ ] `'login'` → existing card (unchanged)
  - [ ] `'passkey'` → key icon, show `rpId` as primary line, `authenticatorName` as secondary, backed-up badge
  - [ ] `'secure_note'` → file-text icon, show `service` (title) as primary, first 80 chars of `noteContent` as secondary (truncated, no reveal in list — only in detail view)
  - [ ] `'payment_card'` → credit-card icon, show `service` (label) as primary, `cardholderName` + last-4 as secondary, masked
- [ ] Extend search to include `rpId`, `rpName`, note content (first 200 chars)
- [ ] Filter chips or icon legend in vault header to filter by credential type

### Sub-task 4+7.4 — i18n
- [ ] Add all new strings to `en.json` + `fr.json` for type selector, form labels, tooltips, PCI disclaimer

---

## Completion Checklist (Final Verification Before Done)

- [x] All new API routes have CSRF protection on mutations
- [x] `ipregistry` API key never in browser bundle (server-side only via IpIntelligenceService)
- [x] No plaintext credential data anywhere (audit log encrypted, share blobs client-side encrypted)
- [x] `credentialType` backwards-compatible (undefined = login, existing vault renders identically)
- [x] PWA service worker denylists `/api/`, `/ws`, `/share/`
- [x] All user-facing strings i18n'd in both `en.json` and `fr.json`
- [x] `npm run lint` passes (tsc --noEmit)
- [x] `npm run build` passes — service worker with 79 precached entries generated
- [x] API smoke tests: audit events, IP policy CRUD, share label, vault manifest/sw.js

---

## Session Resume Instructions

If you are reading this after a session interruption:

1. Run `git status` to see what files were modified.
2. Run `git diff` to see partial changes.
3. Cross-reference modified files against the sub-tasks above to determine what was completed.
4. Find the first `[ ]` (not started) or `[~]` (in progress) item and continue from there.
5. Do NOT re-read `FEATURE_PLANNING.md` from scratch — check the specific section for the sub-task you're resuming.

**Key file locations:**
- New file to create: `web/ipIntelligence.js`
- New file to create: `web/public/manifest.json`
- New file to create: `web/src/components/InstallPrompt.tsx`
- Key files to modify: `web/auth.js`, `web/src/pages/Settings.tsx`, `web/src/pages/AddCredential.tsx`, `web/src/pages/Vault.tsx`, `web/src/types.ts`, `web/vite.config.ts`, `web/src/components/ShareModal.tsx`, `web/src/components/NetworkStatus.tsx`, `web/src/layouts/AppLayout.tsx`
- i18n: `web/src/locales/en.json`, `web/src/locales/fr.json`
