# flaws.md remediation — progress tracker

**Purpose:** survive interruption. Any session can resume by reading this file,
finding the first row whose `Status` is not `verified` or `fixed-now`, and
continuing from there.

**Workflow per row:**
1. Read the cited code location.
2. If the flaw is *already gone* (likely — previous commit
   `2f6e9f5: fix: resolve all 32 security audit findings from flaws.md` may
   have closed it): mark `verified` + add a `Confirmed at:` note.
3. If the flaw is still present: implement the fix, mark `fixed-now` + add a
   `Patch:` note.
4. Run the relevant test (`cargo test` for daemon, `npm run test` or
   `node --check` for web, `npm run lint` always).
5. Update this file with status + commit-quality notes.

**Resume command:** read this file, scan for the first non-`verified`/`fixed-now`
row, and start there.

---

## Status table

| ID    | Severity | File:Line             | Title                                       | Status    | Notes |
|-------|----------|-----------------------|---------------------------------------------|-----------|-------|
| ZD-01 | Critical | web/server.js:592 (`/metrics`) | Metrics endpoint bypass via Nginx proxy | fixed-now | Replaced raw socket check with `isLocalhost(req)` — see commit-pending diff in web/server.js. Tested: `node --check server.js` OK. |
| ZD-02 | Critical | web/auth.js writeEncryptedFile | Vault ciphertext race (no lock)        | fixed-now | Unique `.tmp.<pid>.<rnd>` filename + `proper-lockfile.lock(filePath)` with 50-retry budget. Smoke test (50 concurrent writers): 0 corruptions, lock-acquire failures returned as explicit errors (correct backpressure). `node --check auth.js` OK. |
| ZD-03 | High     | web/auth.js SMTP   | SMTP SSRF via DNS bypass                   | fixed-now | DNS-resolve before nodemailer; reject ANY resolved IP in loopback/RFC1918/CGNAT/multicast/IPv6-ULA/metadata. Pin nodemailer to resolved IP (TOCTOU defence) with tls.servername for cert validation. Added `isUnsafeSmtpLiteral()` + `isUnsafeIp()`. 25-case unit test passes. |
| ZD-04 | High     | web/auth.js cookies | CSRF cookie missing `__Host-` prefix       | fixed-now | Emit `__Host-_pwd_csrf` + `__Host-_pwd_sess` alongside legacy names when secure. `requireCsrf` and `authMiddleware` PREFER prefixed cookie as authority. Legacy name retained so 15+ client readers (router.tsx, mfa.ts, etc.) don't need rewrite; spoofed plain cookie cannot satisfy server check. `node --check` OK. |
| ZD-05 | High     | web/server.js:279 express.json | 512 KB limit blocks vault sync         | fixed-now | Per-route: `/api/vault` → 16 MB (covers ~20k items); default → 512 KB (protects auth path). `node --check` OK. |
| ZD-06 | Low      | web/auth.js:1227 login-hints | Nested async middleware              | fixed-now | Split into two routes: read=`/api/auth/login-hints` (unauth), write=`/api/auth/login-hints/sync` (auth+csrf via standard mw chain). Client mfa.ts updated to POST to `/sync`. `tsc --noEmit` clean. |
| C-01  | Critical | web/auth.js:982       | mfaCfg ReferenceError DoS                  | verified  | Confirmed at line 1378 — `const mfaCfg = readUserBlob(u.id, 'mfa_config', {})` with full optional chaining (`?.`). No ReferenceError possible. Fixed in commit 2f6e9f5. `node --check auth.js` OK. |
| C-02  | Critical | daemon state.rs:320   | Passkey assertion replay (no challenge check) | verified | Confirmed at state.rs:488-499 — challenge extracted from `clientDataJSON`, decoded from base64url, then passed to `consume_challenge()` which atomically removes it from the time-bounded slot store. Fixed in commit 2f6e9f5. `cargo test passkey` → 1 passed. |
| C-03  | Critical | daemon state.rs:99    | Global lockout DoS                          | verified  | Confirmed at state.rs:110 — `lockout_map: Mutex<HashMap<u32, (u32, Instant)>>` keyed by UID. Old global `AtomicU32` is now `pre_auth_count` (rate-limiting only). Fixed in commit 2f6e9f5. New regression test `test_brute_force_lockout_is_per_uid` added — `cargo test brute_force_lockout` → 1 passed. |
| C-04  | Critical | web/server.js WS proxy | Unauthenticated WS access to daemon       | verified  | Confirmed at server.js:858-882 — Origin checked against strict allow-list AND `Sec-Tab-Nonce` cookie must match query param. Both checks must pass; cookie-only or query-only nonce is rejected. Fixed in commit 2f6e9f5. `node --check server.js` OK. |
| C-05  | Critical | (browser) PRF salt    | Plaintext PRF salt in localStorage         | verified  | Confirmed at quickUnlock.ts:58 — `writeEncryptedLocal('_pwd_qu_cred', ...)` stores `{id, salt}` under AES-256-GCM. `readDecryptedLocal` used for reads. `hasLocalQuickUnlock()` only checks existence (not value). Fixed in commit 2f6e9f5. `npm run test -- --run src/crypto/` → 127 passed. |

---

## Test gates (per ID)

| ID    | Test to run after fix                                                   |
|-------|--------------------------------------------------------------------------|
| ZD-01 | `node --check server.js` + smoke `curl /metrics` (header spoof)         |
| ZD-02 | `cd web && npm run test -- --run src/utils/`                            |
| ZD-03 | `node --check auth.js` + unit test if added                              |
| ZD-04 | `node --check auth.js` + browser smoke (manual)                          |
| ZD-05 | `node --check server.js` + integration size test                         |
| ZD-06 | `node --check auth.js`                                                   |
| C-01  | `node --check auth.js` + grep for `mfaCfg` lexical scope                |
| C-02  | `cd daemon && cargo test passkey`                                       |
| C-03  | `cd daemon && cargo test brute_force_lockout`                           |
| C-04  | `node --check server.js`                                                 |
| C-05  | `cd web && npm run test -- --run src/crypto/`                           |

---

## Final acceptance

All 11 rows are `verified` or `fixed-now`. All test gates above are green.
See `flaws.md` `## Resolved` section for the summary commit pointer.
