# PWDnow — Feature Integration Planning
## Meeting Notes: Senior Developer (SD) × Cybersecurity Lead (CSL)
### Features: Sharing UI · Passkey Credential Type · IP-Enriched Audit Log · Secure Note & Card Types · PWA
---

> **Format:** SD = Senior Developer, CSL = Cybersecurity Lead.
> This document is the authoritative reference for the `/plan` session. It captures every architectural decision, security constraint, and implementation boundary before a single line is written.

---

## 0. Baseline State — What Already Exists

**SD:** Before we plan anything, let's be explicit about what's already shipped so we don't duplicate work.

| Feature area | What's already there |
|---|---|
| Credential sharing | Backend fully implemented in `auth.js`: `POST /api/vault/shares`, `GET /api/vault/shares`, `DELETE /api/vault/shares/:shareId`, `GET /api/share/:shareId`. Client-side AES-GCM encryption in `ShareModal.tsx`. Share viewer in `ShareView.tsx`. "Share Item" button present in `Vault.tsx`. |
| Session audit log | `auth.js` tracks sessions to `sessions.enc` per user. IP is SHA-256 hashed with a daily salt. The Settings audit modal shows these sessions. |
| Passkey MFA | Passkey / Touch ID / Windows Hello login-to-PWDnow implemented. This is a different concern from storing third-party passkey metadata inside the vault. |
| Credential notes | `Credential.description` field exists; notes are part of the credential blob. |
| Import/Export | Both sides implemented. |
| PWA | Nothing. Zero. No manifest, no service worker. |

**CSL:** Good baseline. So the gaps are: (a) Settings has no "manage my shares" panel, (b) no IP threat intelligence or blocking, (c) no credential types beyond generic login, (d) no offline PWA. Each of those is a separate risk surface. Let's go one by one.

---

## 1. Feature 3 — Secure Credential Sharing (Settings management panel)

### 1.1 Current Gap
**SD:** The backend and the modal are done. The only missing piece is that users have no way to **see and revoke** active share links. If someone generates 10 shares and then forgets about them, those are live URLs in the wild indefinitely (until TTL expires). We need a "My Active Shares" panel inside Settings.

**CSL:** That gap is significant. A share link contains the share ID in the URL path and the AES-256-GCM key in the fragment. The server stores the encrypted blob + IV. Without revocation UI, a user who accidentally pastes a share link somewhere has no recovery path other than waiting for TTL.

### 1.2 What We Build

**SD:** The `GET /api/vault/shares` endpoint already returns all active shares for the current user — `id`, `expiresAt`, `singleView`, `viewedAt`, `createdAt`. The share record does NOT include the fragment key (server never sees it), so the revocation UI shows metadata only.

**UI location:** Add a new card in Settings inside the Security section, titled "Active Share Links". Place it directly below the existing "Security Audit Log" card.

**Card contents:**
- If zero shares: empty state ("No active share links.")
- If shares exist: table with columns — Credential name (from share record `label` field, we need to store that when creating), Created, Expires, View-once status, Viewed timestamp (if applicable), Revoke button.
- "Revoke All" button at top-right of the card.
- Individual revoke hits `DELETE /api/vault/shares/:shareId` with CSRF token.
- After revoke, re-fetches list.

**SD:** We need a small backend change: the share creation payload currently stores `encryptedBlob`, `iv`, `ttl`, `singleView`. We should also store a `label` (the credential's `service` name, already available in `ShareModal.tsx` via `credential.service`) so the Settings panel can show which credential was shared without needing to decrypt the blob.

**CSL:** Hold on. Storing the service name in plaintext in the share record means someone with filesystem access to `auth_data/vault/<uid>/shares/` can enumerate which services that user has shares for, even if they can't read the credential itself. Is that acceptable?

**SD:** It's a server-mode concern only — daemon mode doesn't use the file-based share store. For server mode, `auth_data/` is already the trust boundary; it requires filesystem access to the server. And the service name alone (e.g. "GitHub") has marginal sensitivity compared to the credential itself. I'd accept that trade for usability.

**CSL:** Agreed. We document it in the security comment. Also: the revoke endpoint must verify that the share belongs to the authenticated user. Check `auth.js` — the `DELETE` handler already does `userSharesDir(req.user.id)` which namespace-scopes the path. Good.

### 1.3 Files Touched
- `web/auth.js` — `POST /api/vault/shares` add `label` field to stored record.
- `web/src/components/ShareModal.tsx` — include `label: credential.service` in the POST body.
- `web/src/pages/Settings.tsx` — add "Active Share Links" card section; `useEffect` on mount to `GET /api/vault/shares`.
- `web/src/locales/en.json` + `fr.json` — new i18n keys.

### 1.4 Security Checklist
- [x] Server never sees the AES key (it's in the URL fragment, never sent to server).
- [x] Revoke path is namespace-scoped per user.
- [ ] Add CSRF to revoke call in the new Settings panel.
- [ ] Rate-limit `GET /api/vault/shares` (already rate-limited by auth middleware? Verify).
- [ ] Revoke-all must iterate and call individual deletes or add a bulk endpoint to `auth.js`.

---

## 2. Feature 4 — Passkey Credential Type (Third-Party Passkey Metadata Storage)

### 2.1 Scope Definition
**CSL:** I want to be precise about what we are and are NOT doing here. We are NOT building a software passkey authenticator (where PWDnow acts as the WebAuthn authenticator for third-party sites). That requires a browser extension and is Feature 1. What we ARE building is a new **credential type** called "Passkey" that lets a user document: which sites they have passkeys on, what the credential ID is, which device/authenticator holds it, and relevant metadata. This is analogous to keeping a record in a physical notebook that says "I have a passkey for GitHub, stored in my YubiKey 5C, credential ID abc123."

**SD:** Exactly. The private key stays in the hardware authenticator — we never touch it. We're storing user-controlled metadata, encrypted like any other credential.

### 2.2 Type System Changes

**File: `web/src/types.ts`**

Add `credentialType` discriminant to `Credential`:

```typescript
export type CredentialType = 'login' | 'passkey' | 'secure_note' | 'payment_card';

export interface Credential {
  // ... existing fields ...
  credentialType?: CredentialType;   // undefined = 'login' for backwards compat
  // Passkey-specific (credentialType === 'passkey')
  rpId?: string;                      // "github.com"
  rpName?: string;                    // "GitHub"
  credentialId?: string;             // base64url credential ID from authenticator
  userHandle?: string;               // base64url user handle (opaque, not username)
  authenticatorName?: string;        // "YubiKey 5C NFC", "iPhone Face ID", etc.
  backedUp?: boolean;                // Is the passkey backed up (synced)?
  // Secure Note fields (credentialType === 'secure_note')
  noteContent?: string;              // encrypted note body
  // Payment Card fields (credentialType === 'payment_card')
  cardholderName?: string;
  cardNumber?: string;               // stored encrypted, displayed masked
  cardExpiry?: string;               // "MM/YYYY"
  cardCvv?: string;
  cardBillingAddress?: string;
  cardType?: string;                 // "visa" | "mastercard" | "amex" | "discover" (derived client-side)
}
```

**CSL:** A few security notes on the passkey fields. The `credentialId` in WebAuthn is NOT secret — it's a public handle used by the relying party to look up the credential. But some users may not want it discoverable outside their vault, so encrypting it is correct. The `userHandle` is also not a secret (it's just the user's opaque ID from the RP) but same rationale applies. We should never add a field to store or prompt for private key material.

**SD:** Agreed. We should add a tooltip in the AddCredential form that explicitly says "Private key stays on your authenticator — we never store it here."

**CSL:** Also: `cardNumber` and `cardCvv` are PAN data (payment card industry scope). Storing them is legal but we need to make clear in the UI that this is unvalidated personal storage and NOT PCI-DSS certified storage. A small disclaimer in the UI is enough. We're not processing payments.

### 2.3 AddCredential Form Changes

**File: `web/src/pages/AddCredential.tsx`**

1. Add a **type selector** at the top of the form: 4 cards — "Login", "Passkey", "Secure Note", "Payment Card". Default: "Login".
2. Conditionally render form sections based on selected type:
   - **Login:** existing form (service, url, username, password, notes, OTP, etc.)
   - **Passkey:** service (website name), rpId (Relying Party ID), rpName, username (display), credentialId, userHandle, authenticatorName, backedUp toggle, notes
   - **Secure Note:** title (maps to `service`), noteContent (textarea, multi-line), no URL/username/password fields
   - **Payment Card:** cardholder name, card number (masked input), expiry (MM/YYYY picker), CVV, billing address, notes

**SD:** For the card number input, we detect the card type (Visa = starts with 4, Mastercard = 51-55, Amex = 34/37, Discover = 6011) client-side for cosmetic purposes only and store the detected type in `cardType`. We never send the card number to any external service.

**CSL:** The card number must be treated like a password field: `type="password"` by default, reveal on toggle. CVV same. Auto-clear clipboard after 10 seconds if copied (use `secureClipboard()`). I also want to make sure we're not logging these anywhere in the server. The credential blob is opaque to the server — it just stores the encrypted bytes — so this is fine by design.

### 2.4 Vault View Changes

**File: `web/src/pages/Vault.tsx`**

- Passkey cards: show passkey icon (key icon from lucide), show `rpId`, `authenticatorName`, backed-up badge. Don't show password field (there is none).
- Secure Note cards: show document icon, show first 100 chars of `noteContent` as preview, truncated.
- Payment Card cards: show credit card icon, show last 4 of `cardNumber` (derived client-side, never sent to server), cardholder name, masked expiry.

**SD:** The vault search already searches `service`, `username`, `url`, `tags`. We need to extend it to also search `rpId`, `rpName` for passkeys, and the note title for secure notes.

### 2.5 Files Touched
- `web/src/types.ts` — extend `Credential`, add `CredentialType`
- `web/src/pages/AddCredential.tsx` — type selector, conditional form fields
- `web/src/pages/Vault.tsx` — type-aware credential cards, extended search
- `web/src/locales/en.json` + `fr.json` — new i18n keys
- No daemon or server changes needed — the encrypted blob is already schema-agnostic.

---

## 3. Feature 5 — IP-Enriched Audit Log + Threat Blocking

### 3.1 Architecture Overview

**SD:** This is the most complex feature of the batch. Let me break it into three orthogonal sub-systems:
1. **IP Intelligence service** — ipregistry.co lookup, caching, result normalization
2. **Threat blocking middleware** — Express middleware that blocks Tor/VPN/proxy/abuser/attacker IPs before any route handler runs
3. **Rich audit event log** — replaces the existing session-only log with a full CRUD event log per user

**CSL:** I want to discuss the blocking middleware first because it has the highest security impact and the most failure modes.

### 3.2 Threat Blocking Middleware

**CSL:** The design constraint: if `IPREGISTRY_API_KEY` is not set, the middleware must be a no-op — not a hard block of all traffic. This is an open-source project; not everyone will have an API key. The middleware only activates when the key is present.

**SD:** Agreed. Environment variable: `IPREGISTRY_API_KEY`. If unset, skip all IP intelligence.

**Blocking criteria (user configurable via Settings toggle, default ON when key is present):**
- `security.is_tor` — Tor exit node
- `security.is_proxy` — open proxy / transparent proxy
- `security.is_vpn` — commercial VPN exit
- `security.is_abuser` — IP flagged in abuse databases
- `security.is_attacker` — IP flagged as active attacker / scanner

**CSL:** I'm going to push back on blanket VPN blocking. Many security-conscious users will legitimately use a VPN to access their password manager. Blocking VPNs by default will lock out a large portion of the security-savvy user base. My recommendation: block Tor, proxy, abuser, attacker by default; make VPN blocking opt-in via a separate Settings toggle.

**SD:** Good point. So the Settings UI will have:
- "Block Tor / Anonymous Networks" (default ON, covers `is_tor`)
- "Block Known Proxies" (default ON, covers `is_proxy`)
- "Block VPN Exits" (default OFF, covers `is_vpn`)
- "Block Abusive IPs" (default ON, covers `is_abuser` + `is_attacker`)

These settings are stored per-installation in `auth_data/.ip_policy.json` (or environment variables). Since this affects all users equally (it's a server-level policy, not per-user), the admin/setup flow should configure it.

**CSL:** Where do we store the per-user preferences vs server-level preferences? IP blocking should be server-level — if the server admin wants to block Tor, it applies to ALL users. Individual users shouldn't be able to opt out of server-level threat blocking. However, the "allow VPN" toggle could be per-user (stored in their profile).

**SD:** Fine. IP blocking policy in `auth_data/.ip_policy.json` (admin-level, read by server on startup). Per-user VPN override stored in `profile.enc` (user-level). The Settings UI reflects the server policy and, where applicable, shows the user's personal override toggle.

**Implementation — IP intelligence service (`web/ipIntelligence.js`, new file):**

```
IpIntelligenceService
  - constructor(apiKey)
  - async lookup(ip): IpRecord | null
    - Returns null if apiKey is empty, or if ip is loopback/private range
    - Checks in-memory LRU cache (max 500 entries, TTL 1 hour)
    - On cache miss: GET https://api.ipregistry.co/{ip}?key={apiKey}&fields=security,location,connection,type,hostname
    - Normalizes response to IpRecord: { ip, country, city, region, org, connectionType, isTor, isProxy, isVpn, isAbuser, isAttacker, isCloudProvider, riskFlags[] }
    - Handles API errors gracefully (log + return null, do not throw)
  - isThreat(record, policy): boolean
  - getRiskFlags(record): string[]
```

**Private ranges to skip:** `127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`. Never hit the API for these — they're local/LAN/loopback.

**CSL:** One subtle attack: an adversary could flood the server with requests from different IPs to drain the API quota and then bypass blocking once the key quota is exhausted. The middleware must handle API rate-limit responses (`429`) by failing-safe: if ipregistry returns 429, fail OPEN (allow the request) and log a warning. We're not in a position to deny service to legitimate users because of API quota. Document this trade-off.

**SD:** I'll also add an in-process request deduplicator — if 10 requests come in simultaneously from the same IP before the cache warms, only one lookup fires to ipregistry; the others wait on the same promise.

### 3.3 Rich Audit Event Log

**SD:** The current `sessions.enc` only tracks login sessions. We need a separate `audit_log.enc` per user that records:

```typescript
interface AuditEvent {
  id: string;           // UUIDv4
  ts: number;           // Unix ms
  action: AuditAction;
  ip: string;           // full IP (NOT hashed — it's encrypted at rest in audit_log.enc)
  ipInfo?: IpRecord;    // enriched metadata from ipregistry
  userAgent: string;
  resourceId?: string;  // credential ID if applicable
  resourceLabel?: string; // credential service name if applicable
  success: boolean;
  riskFlags: string[];  // ["tor", "proxy"] etc.
  detail?: string;      // e.g. "Password changed"
}

type AuditAction =
  | 'login'        | 'login_failed'   | 'logout'
  | 'credential_read' | 'credential_created' | 'credential_updated' | 'credential_deleted'
  | 'share_created'   | 'share_revoked'
  | 'mfa_changed'     | 'password_changed'   | 'profile_updated'
  | 'emergency_access_requested' | 'forensic_wipe_triggered'
  | 'settings_ip_blocked';
```

**CSL:** Storing the full IP address in `audit_log.enc` is correct — the file is encrypted at rest with the user's HKDF-derived key. The IP is essential for the audit log to be useful. The existing `sessions.enc` was hashing the IP for a different reason (it was shown in a modal and we didn't want to display raw IPs to the user). For the new audit log, we display the enriched info (city, country, org) and only show the IP if the user explicitly asks to reveal it.

**Storage:** `auth_data/vault/<uid>/audit_log.enc`. Encrypted with `userInfo(uid, 'audit_log')` key. Max 1000 entries; FIFO rotation (drop oldest when full). Atomic write via temp file + rename.

**API routes (add to `auth.js`):**
- `GET /api/audit/events?limit=50&offset=0&action=...&since=...` — paginated, filtered
- `DELETE /api/audit/events` — clear the log (user's own data, requires CSRF)

**Where to hook audit events:**
- Login success/failure: already in the `/api/auth/login` handler — augment `recordSession` call
- Logout: `/api/auth/logout` handler
- Credential CRUD: wrap the `GET/POST/PUT/DELETE /api/vault/credentials` handlers
- Share create/revoke: the share endpoints
- MFA changed / password changed: existing profile/MFA handlers
- Settings IP blocked: the blocking middleware itself records the event under a system-level key (no uid because we don't know who it was — store in a server-wide `audit_blocked.log` file, NOT in a user's vault)

**CSL:** For `credential_read` events: recording every single GET credential request will bloat the log extremely fast if the user has an active browsing session. Consider only recording the first read of a credential per session, or only recording reads that match a risk pattern (non-local IP, etc.).

**SD:** Good call. Policy: `credential_read` events are recorded only when `riskFlags.length > 0` (i.e., the IP has a threat flag) OR when the IP differs from the last-seen IP for that session. Normal reads from a trusted IP in an active session are skipped. This keeps the log meaningful without noise.

### 3.4 Settings UI Changes

**File: `web/src/pages/Settings.tsx`**

The existing "Security Audit Log" card and modal need significant upgrades:

**New Settings card (replace/augment existing):**

Card: "Security & Threat Policy"
- ipregistry API Key input: `[___________________] [Save]` — saved to user's `profile.enc`
- Shows "API key active" / "No API key — IP threat detection disabled" status
- Link: "Get a free key at ipregistry.co" (static documentation URL, not dynamic)
- Toggles:
  - Block Tor / Anonymous Networks [ON]
  - Block Known Proxies [ON]
  - Block VPN Exits [OFF] — with note "(may affect users on corporate/privacy networks)"
  - Block Abusive & Attacking IPs [ON]
- "Save Policy" button — writes to server-level policy (Settings modal, admin context)

**Audit Log modal (upgrade existing):**

Replace the current session-based table with a richer layout:
- Tabs: "All Events" | "Logins" | "Credential Access" | "Security Events"
- Columns: Timestamp | Action | Location (flag emoji + city + country) | Network (org name / "Tor" / "VPN") | Risk | Resource | Status
- Risk column: green shield (clean) / yellow warning (VPN/cloud) / red alert (Tor/proxy/attacker/abuser)
- Expand row → show full `ipInfo` details: ASN, org, connection type, full IP (masked by default, reveal on click)
- "Export CSV" button (already exists, augment with new fields)
- "Clear Log" button with confirmation dialog (calls `DELETE /api/audit/events`)

**CSL:** The IP address in the expanded row must be masked by default (show `*.*.*.xxx` or similar). The user can click a reveal button to see the full IP. This prevents shoulder-surfing.

### 3.5 Files Touched
- `web/ipIntelligence.js` — **new file**, IpIntelligenceService class
- `web/auth.js` — blocking middleware, audit hooks, `GET/DELETE /api/audit/events`, `userInfo` key for `audit_log`
- `web/.env` / `web/.env.example` — add `IPREGISTRY_API_KEY=` (empty, documented)
- `web/src/pages/Settings.tsx` — upgraded audit modal, new IP policy card
- `web/src/locales/en.json` + `fr.json` — new i18n keys

### 3.6 Security Checklist
- [ ] ipregistry API key NEVER goes into the browser bundle (C-04 rule). All calls go through the server.
- [ ] Private/loopback IP ranges skip the lookup entirely.
- [ ] LRU cache with TTL prevents quota exhaustion on repeated IPs.
- [ ] Request deduplicator prevents parallel API calls for same IP.
- [ ] 429 / API error → fail open (allow request, log warning).
- [ ] `audit_log.enc` stores full IP (acceptable — encrypted at rest).
- [ ] IP displayed to user masked by default; full reveal on click.
- [ ] `DELETE /api/audit/events` requires CSRF token.
- [ ] Server-level policy JSON (`auth_data/.ip_policy.json`) not writable via any API (admin filesystem only).
- [ ] `credential_read` audit events throttled to only high-risk or IP-change events to prevent log flooding.

---

## 4. Feature 7 — Secure Note & Payment Card Credential Types

### 4.1 Overlap With Feature 4
**SD:** Feature 4 (Passkey type) already adds `credentialType` to `Credential` and the type selector to `AddCredential`. Feature 7 adds two more types to the same type system. These must be implemented in the same pass — they share the same `CredentialType` enum and the same type selector UI.

**CSL:** Confirm. Also, "Secure Note" already has partial support via the `description` field on existing credentials. The new standalone Secure Note type is a first-class credential entry with `service` = title and `noteContent` = body, with no username/password/URL fields rendered. The difference from the current `description` field: `description` is a secondary annotation on a login credential; `noteContent` is the primary content of a note credential.

### 4.2 Secure Note
**SD:** Form fields for secure note:
- Title (maps to `service`, required)
- Content (`noteContent`, large textarea, max 50KB client-side validation)
- Tags (same as existing)
- Folder (same as existing)

**CSL:** The content is part of the credential blob — it goes through the same AES-GCM / DEK encryption path as any credential. The blob size limit in the daemon is the constraint. 50KB is conservative and safe.

No username, no password, no URL, no OTP, no phone number fields. The form must not render these when type = `secure_note`.

### 4.3 Payment Card
**SD:** Form fields:
- Card label (maps to `service`, e.g. "Amex Business Card")
- Cardholder name (`cardholderName`)
- Card number (`cardNumber`, masked input, pattern-validated for 13-19 digits)
- Expiry (`cardExpiry`, MM/YYYY format)
- CVV (`cardCvv`, 3-4 digits, masked)
- Billing address (`cardBillingAddress`, textarea)
- Notes (`description`)

Card type detection (cosmetic, client-side only, not stored):
- Visa: starts with `4`
- Mastercard: starts with `51–55` or `2221–2720`
- Amex: starts with `34` or `37`
- Discover: starts with `6011`, `622`, `644–649`, `65`

**CSL:** The card number and CVV fields must use the existing `secureClipboard()` utility when copied. No plain clipboard writes. Auto-clear after 10 seconds. The card number input should be displayed as `****-****-****-1234` (last 4 visible) by default with a reveal toggle — same pattern as password fields.

**SD:** The `cardType` field stores the detected type (e.g. "visa") for the icon in the vault list view. This is derived from the number at display time, not stored. Actually — let's store it so we don't need the number to render the card icon when the number is hidden. Store the derived type string.

**CSL:** Important: we do NOT implement any Luhn algorithm validation that sends the number anywhere. All card number handling is local and purely cosmetic/organizational.

### 4.4 Files Touched
Same as Feature 4 — these types co-land with the passkey type in the same files.
- `web/src/types.ts`
- `web/src/pages/AddCredential.tsx`
- `web/src/pages/Vault.tsx`
- `web/src/locales/en.json` + `fr.json`

---

## 5. Feature 10 — Progressive Web App (PWA / Offline Mobile)

### 5.1 Architecture

**SD:** PWA has two goals: (a) installability — add to home screen on iOS/Android/desktop; (b) offline operation — the app shell loads even without a network connection.

**CSL:** The security surface for a PWA is larger than a normal web app because the service worker is a privileged network proxy. I have strong opinions about what the service worker must and must NOT cache. Let me be explicit.

**Service worker MUST cache (cache-first, offline-first):**
- App shell: `/` (index.html), all JS/CSS chunks, fonts, icons
- Static assets: images, SVGs
- `/locales/**` translation files

**Service worker must NEVER cache:**
- `/api/**` — any API response containing session tokens, credentials, vault data
- `/ws` — WebSocket (can't be cached anyway)
- Any response with `Set-Cookie` or `Authorization` headers
- Any response with `Cache-Control: no-store`

**SD:** Implementation: use `vite-plugin-pwa` with Workbox. Configuration strategy:
- `generateSW: true` (Workbox generates the service worker)
- `workbox.runtimeCaching`: network-first for navigation, cache-first with TTL for static assets
- `workbox.navigateFallback`: `'/'` (SPA routing)
- `workbox.navigateFallbackDenylist`: `[/^\/api\//]` — API calls must never fall back to the SPA

**CSL:** On iOS, PWAs don't support persistent service workers the same way as Chrome/Android. The offline vault access depends on whether the vault data is in localStorage (daemon/local mode) or on the server (server mode). For server mode: offline = no new data, but the cached app shell loads and shows a "You're offline" banner. For daemon/local mode: credentials are in encrypted localStorage and are available offline.

**SD:** Correct. The NetworkStatus component already detects offline state. We extend it: when offline in daemon mode, show "Vault available in read-only offline mode." When offline in server mode, show "Vault unavailable — connect to sync."

### 5.2 Manifest

**File: `web/public/manifest.json`**

```json
{
  "name": "PWDnow",
  "short_name": "PWDnow",
  "description": "Zero-knowledge local-first password manager",
  "start_url": "/",
  "display": "standalone",
  "orientation": "portrait",
  "background_color": "#0f0f0f",
  "theme_color": "#0f0f0f",
  "scope": "/",
  "icons": [
    { "src": "/icons/icon-192.png", "sizes": "192x192", "type": "image/png" },
    { "src": "/icons/icon-512.png", "sizes": "512x512", "type": "image/png" },
    { "src": "/icons/icon-512-maskable.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable" }
  ]
}
```

**CSL:** The `start_url` should NOT be `/login` — it should be `/` and let the existing auth guard redirect as needed. If we hardcode `/login`, a user who saved the PWA while logged in will always hit the login screen on cold open even if the session cookie is valid.

**SD:** Icons: we need to create 192×192, 512×512, and a maskable 512×512 variant. The maskable icon needs safe-zone padding (the icon content inside 80% radius). I'll use the existing PWDnow logo/lock icon as the base.

### 5.3 Install Prompt

**SD:** Add an `InstallPrompt` component that listens for the browser `beforeinstallprompt` event, stores it, and shows a subtle banner ("Install PWDnow for offline access") with "Install" and "Dismiss" buttons. Persist dismissal in localStorage so it doesn't reappear.

**CSL:** The banner must not appear on pages that don't require auth (login, register, setup) — we don't want to prompt "install for offline access" to someone who hasn't even logged in yet.

### 5.4 `vite.config.ts` Changes

```typescript
import { VitePWA } from 'vite-plugin-pwa';

VitePWA({
  registerType: 'autoUpdate',
  includeAssets: ['favicon.ico', 'icons/*.png'],
  manifest: false, // use public/manifest.json
  workbox: {
    globPatterns: ['**/*.{js,css,html,ico,png,svg,woff2}'],
    navigateFallback: '/',
    navigateFallbackDenylist: [/^\/api\//, /^\/ws/, /^\/share\//],
    runtimeCaching: [
      {
        urlPattern: /^\/locales\//,
        handler: 'CacheFirst',
        options: { cacheName: 'locales', expiration: { maxAgeSeconds: 86400 } }
      }
    ]
  }
})
```

**CSL:** The `navigateFallbackDenylist` for `/share/` is important — share view pages are public and unauthenticated. If a share link is cached by the service worker and then served stale after the share expires/is revoked, the user could see a cached "still valid" page. Deny-listing `/share/` forces a live network request.

### 5.5 Files Touched
- `web/package.json` — add `vite-plugin-pwa` dependency
- `web/vite.config.ts` — VitePWA plugin config
- `web/public/manifest.json` — **new file**
- `web/public/icons/icon-192.png`, `icon-512.png`, `icon-512-maskable.png` — **new files** (PNG assets)
- `web/src/components/InstallPrompt.tsx` — **new component**
- `web/src/layouts/AppLayout.tsx` — mount `<InstallPrompt />`
- `web/src/components/NetworkStatus.tsx` — extend offline messaging for daemon vs server mode
- `web/src/locales/en.json` + `fr.json` — i18n keys for install prompt, offline messages

### 5.6 Security Checklist
- [ ] Service worker never caches `/api/**`, `/ws`, `/share/**`
- [ ] `Cache-Control: no-store` set on all `/api/auth/**` responses in `auth.js`
- [ ] Install prompt not shown on unauthenticated pages
- [ ] `start_url: "/"` not hardcoded to `/login`
- [ ] Workbox `cleanupOutdatedCaches: true` to prevent stale cache accumulation

---

## 6. Implementation Order and Dependencies

**SD:** Features 4 and 7 are tightly coupled (same type system) — they must land in one commit. Features 3, 5, and 10 are independent of each other and of 4/7.

**CSL:** Feature 5 (IP blocking) has the highest security priority. If a malicious actor is currently accessing this instance from a Tor exit, we want that blocked ASAP.

### Recommended Order

```
Phase 1 (independent, can be sequenced)
  1. Feature 5 — ipIntelligence.js + blocking middleware + audit hooks  [highest priority]
  2. Feature 3 — Settings "My Active Shares" panel                       [backend already done]
  3. Feature 10 — PWA: manifest + service worker + install prompt        [no backend changes]

Phase 2 (co-landed, share type system)
  4. Feature 4 + 7 — CredentialType enum + AddCredential type selector + Vault display
```

---

## 7. Cross-Feature Constraints

1. **No secrets in the browser bundle** (C-04): ipregistry API key is server-side only. ShareModal key is ephemeral in memory. Payment card numbers never sent to server in plaintext.
2. **CSRF on all mutations**: all new POST/DELETE routes must require `X-CSRF-Token`.
3. **Audit log encryption**: `audit_log.enc` uses the same `writeEncryptedFile` / `readEncryptedFile` pattern as other per-user files.
4. **i18n**: every new user-facing string in `en.json` + `fr.json` simultaneously.
5. **Credential type backward compat**: `credentialType` is optional. `undefined` means `'login'`. Existing credentials render identically.
6. **Service worker never caches sensitive responses**: documented and enforced via `navigateFallbackDenylist` + `Cache-Control: no-store` on auth routes.

---

## 8. Open Questions (To Resolve Before `/plan`)

1. Where exactly should the "Active Share Links" card sit in Settings — before or after the Audit Log card?
2. Should the IP blocking policy be configurable per-user or only at the server level? (**Tentative:** server-level blocking, user-level VPN override.)
3. For payment cards, should we show an auto-detected card network logo (Visa/MC/Amex icons) in the vault list, or keep it text only?
4. PWA icons: use existing PWDnow lock/shield icon at what color palette? Dark background `#0f0f0f` with primary brand color?
5. Should `audit_log.enc` store `ipInfo` full enrichment object per event (increases size) or only the risk flags + city/country (compact)? (**Tentative:** compact by default, store full object only when `riskFlags.length > 0`.)
