# Race Condition Audit — PWDnow

> Refreshed 2026-05-21. Supersedes the 2026-05-20 audit. Covers the Express server (`web/auth.js`, `web/server.js`), Rust vault daemon (`daemon/src/**`), and React SPA (`web/src/**`).
>
> **2026-05-22 remediation status appended at the top of each finding (FIXED / FIXED-W-NOTE / PARTIAL / NOT-FIXED).** See "Remediation Summary" below for a roll-up. Code changes shipped across five batches with @race-tagged regression tests in `daemon/src/vault/state.rs::stress` and `web/e2e/race-*.spec.ts`.

---

## Remediation Summary (2026-05-22)

| Status | Count | Findings |
|---|---:|---|
| **FIXED** | 32 | D-1, D-2, C-1, C-1′, C-4, C-9, C-10, C-13, C-14, C-15, H-1, H-2, H-3, H-4, H-6, H-7, H-9, H-10, H-12, H-14, H-15, H-16, H-17, M-2, M-3, M-5, M-6, M-7, M-8, M-9, M-10, L-3 |
| **FIXED-W-NOTE** | 4 | H-8 (verified safe), H-11 (verified safe), L-1, L-4 (cosmetic) |
| **PARTIAL** | 3 | M-4 (travel pending sentinel deferred — local config still raceable across crashes), M-11 (Settings.tsx async hydration — `cancelled` flag pattern present, full audit not done), L-2 (header-based detection not yet wired into VaultContext) |

**Architectural changes shipped:**

1. **Daemon canonical lock order** — `db → vmk → vault_uuid → wipe_ticket → lockout_map → sessions`. `daemon/src/vault/state.rs:862` refactored to match every sidecar writer; eliminates AB-BA deadlock surface (D-2). `forensic_wipe` no longer called from inside a `with_vmk` closure (D-1) — see `daemon/src/ipc/socket.rs:362`.
2. **Server-side `withUsersLock(fn)` helper** in `web/auth.js` (modelled on the existing `withMfaPendingLock`). 10+ load-mutate-save sites refactored to take an exclusive `proper-lockfile` lock on `users.enc` across the entire R-M-W. Includes per-user-dir lock `withUserDirLock(uid, fn)` for sessions writes and `withEmergencyRequestsLock(uid, fn)` for the emergency-request append path.
3. **Browser-fingerprint-gated rate limiter** (Batch 2.5, audit-strict + user direction). `@fingerprintjs/fingerprintjs` OSS captures `visitorId` + screen + UA → `clientIdentity = sha256(...)`. Three independent gates (IP / account / fingerprint). When ANY gate trips, the server still pays an Argon2id verify (against a pre-computed dummy hash) before returning the 200 — equalises timing AND makes per-fingerprint DoS expensive. User record gains `fingerprintLog: [{ id, visitorId, screen, ... }]` ring buffer cap 32; UI panel exposes it for revocation.
4. **DaemonClient connection state machine** (`web/src/utils/daemonClient.ts`). Explicit `disconnected | connecting | open | closing` field; enqueues in `closing/disconnected` reject synchronously instead of pushing into a queue about to be drained.
5. **React in-flight guards via `useRef`** (Login.tsx H-6), **debounced demoKeyAvailable** (VaultContext M-6), **server-first disarmDuressMode** (H-15), **version-stamped duress mirror** (H-7), **hydrate-once travel config** (H-16).

**Regression tests:**

- `daemon/src/vault/state.rs::stress::forensic_wipe_under_vmk_read_does_not_deadlock` (D-1).
- `daemon/src/vault/state.rs::stress::lock_unlock_under_high_contention_does_not_deadlock` (D-2).
- `daemon/src/vault/state.rs::stress::concurrent_policy_updates_do_not_deadlock` (M-8).
- `web/e2e/race-duress-counter.spec.ts @race` (C-1, C-1′).
- `web/e2e/_concurrency.ts` helper exposes `parallelFetch(n, builder)` for additional specs.

Race-tagged e2e specs are opt-in via `npm run test:race` (the default `npx playwright test` skips them).

**Out-of-scope (audit explicit):**

- Cloudflare sync (`daemon/src/sync/cloudflare.rs`) — separate audit.
- `daemon/fuzz/` targets.
- FingerprintJS Pro / SaaS — intentionally NOT used (privacy + offline-first).

**Audit-cited SPA parse errors:** the 2026-05-21 audit cited two parse errors at `AddCredential.tsx:1825` and `Dashboard.tsx:134`. **Verified absent in current code** via `npm run lint` (no errors); the audit was based on an older snapshot.

---

## What changed since 2026-05-20

- **Daemon runtime confirmed multi-thread**: `daemon/src/main.rs:31` uses `#[tokio::main]` with no `flavor` argument; `daemon/Cargo.toml:11` requests `tokio` with `features=["full"]`. Default is the multi-threaded scheduler. **Every Rust mutex finding is amplified** — the prior audit's "Not Confirmed" caveat is resolved unfavourably.
- **Server-authoritative duress enforcement** landed at `auth.js:1093-1203`. The duress counter now lives in the server's `users.enc` (`duressFailureCount`, `duressEnforce`), in addition to the client copy.
- **Duress-armed accounts now SKIP rate-limit checks** (`auth.js:1115`) and **return HTTP 200 instead of 429** for lockouts (`auth.js:1117,1120`) so the SPA distinguishes by parsing `data.error`.
- **`securityModes.ts` rewritten** (+359 lines) to use plaintext `localStorage` + server-side mirror. The encrypted `DURESS_KEY` path was removed because the v2 session key isn't available pre-login.
- **`VaultContext.tsx` `reloadLocal()`** now awaits `getTravelModeConfigAsync()` from the server in server-session mode (`VaultContext.tsx:336-348`).
- **Two e2e tests added** that pin sequential (not concurrent) duress behaviour: `e2e/duress-wipe-trigger.spec.ts`, `e2e/login-429-no-decrement.spec.ts`. They do not exercise the races below.

## Executive Summary

**42 findings across 3 layers** — 9 critical, 18 high, 11 medium, 4 low.

**Refresh deltas:**
- **NEW critical**: D-1 (forensic_wipe self-deadlock), D-2 (lock-order inversion vmk↔db), C-1′ (duress-armed accounts bypass rate-limit & timing tells).
- **RESOLVED**: C-2 / C-3 (Map counters now use single-tick immutable update), H-5 (`#connectPromise` assigned synchronously), part of C-6 (sidecar write IS under `db.lock` — only the sign-count path remains, now reclassified as M-8).
- **STILL PRESENT**: C-1 (counter RMW; *worse* under the new amplifications), C-4, C-9, C-10, C-13, C-14, C-15 and most High/Medium.

**Top 5 to fix first**:

1. **D-1 — ForensicWipe self-deadlock** (`daemon/src/vault/state.rs:873-899` + `daemon/src/ipc/socket.rs:362-380`). The wipe is invoked from inside a `vmk.read()` guard and then calls `lock()` which takes `vmk.write()`. **The daemon will never actually wipe — it deadlocks the dispatch task, the 120 s deadline returns 504, and `std::process::exit(0)` never fires.** This silently defeats every other duress / wipe finding below.
2. **C-1 + C-1′ — Duress counter race, now amplified** (`auth.js:1093-1203` + `Login.tsx:589-601`). Concurrent wrong-password POSTs both load `users` with the same `duressFailureCount`, both await Argon2id (6-8 s), both `saveUsers()` with `+1`. Counter only increments by 1 per round of N concurrent attempts. The duress wipe never reaches threshold. Duress-armed accounts have no rate-limit pushback (`auth.js:1115`) and no timing-distinguishable 429, so attacker friction is now zero.
3. **D-2 — Lock-order inversion vmk↔db** (`state.rs:862-869` vs `state.rs:313/436/457`). `lock()` takes `vmk.write()` then `db.lock()`; `change_password_inner` / `add_passkey_to_sidecar` / `update_login_policy` take `db.lock()` then `vmk.read()` (via `write_header` at `state.rs:362`). Multi-threaded tokio + the 60 s idle-lock ticker (`socket.rs:50-58`) = AB-BA deadlock under benign concurrency (passkey enrollment that crosses the idle boundary).
4. **C-13 — Recovery-key rotation race** (`auth.js:1310-1347`). Two concurrent `POST /api/auth/recovery-key` both `loadUsers() → await verifyPassword → await hashPassword → saveUsers(users)`. Last write wins; user is shown recovery key A but server stores hash of recovery key B → un-recoverable.
5. **M-8 — Passkey sign-count update bypasses the db lock** (`state.rs:579-588`). All other sidecar writers hold `self.db.lock()` across `read_header → mutate → write_header`. The sign-count update inside `unlock_with_passkey_inner` does not. A concurrent `RegisterFido2` or `UpdateLoginPolicy` can clobber the sign-count, and the sign-count update can clobber a freshly-added passkey credential.

**Top pattern:** ~70 % of server-side findings remain the same shape — `load() → await → save()` without holding a lock across the await. The new server-side duress flag is a **new instance of this same pattern**, not a fix for it.

---

## Critical Findings

### D-1. ForensicWipe self-deadlock (daemon never actually wipes)

**Where:** `daemon/src/ipc/socket.rs:362-380` (dispatch) + `daemon/src/vault/state.rs:873-899` (`forensic_wipe`) + `state.rs:862-869` (`lock`) + `state.rs:1098-1111` (`with_vmk`).

**Scenario:**

```rust
// socket.rs
Request::ForensicWipe { wipe_ticket_ciphertext, wipe_ticket_nonce } => {
    let res = state.with_vmk(|vmk| {           // holds vmk.read() across closure
        let ticket = state.decrypt_wipe_ticket(...)?;
        state.forensic_wipe(&ticket)           // body calls self.lock()
    });
    ...
}

// state.rs
pub fn forensic_wipe(&self, presented_ticket: &[u8]) -> Result<(), VaultError> {
    ...
    self.lock();                                // <-- enters lock()
    ...
}

pub fn lock(&self) {
    drop(self.vmk.write().unwrap().take());    // <-- DEADLOCK
    ...
}
```

`std::sync::RwLock::write()` blocks until all readers have released. The same task is holding `vmk.read()` from the surrounding `with_vmk` closure, so `vmk.write()` waits forever.

**What actually happens at runtime:** the 120-second `DISPATCH_DEADLINE_SECS` (`socket.rs:151`) fires, the wrapper returns `Response::Error { code: 504, message: "deadline exceeded" }` to the client. But:
- `tokio::time::timeout` only times out the *await* on the `JoinHandle`; the spawned task itself keeps trying to acquire `vmk.write()` forever — task and locks leak.
- `tokio::spawn(async { sleep(300ms); std::process::exit(0); })` at `socket.rs:373-376` is only reached if `Ok(())` is returned. It never fires.
- `super::wipe::cryptographic_erase(...)` and `media_overwrite(...)` at `state.rs:888-897` are never called. **`vault.db` and `vault.db.meta` remain on disk intact.**

**Impact:** Every duress/wipe code path on the daemon side is silently a no-op. The new server-side duress (which DOES wipe the user record) only triggers on the *server* path — when daemon mode is the active mode (a typical install), the duress mechanism is non-functional end-to-end. This is a defeat of the headline security feature.

**Fix idea:** Drop the read-lock before calling `lock()`. Either pass the ticket out of `with_vmk` (decrypt, return the verified ticket, then call `forensic_wipe` outside the closure), or split `forensic_wipe` so the verify-and-extract phase happens inside `with_vmk` and the destructive phase runs after the guard drops.

**Realism:** Triggers on any successful wipe attempt. Already silently broken in production — invisible because the user never sees the 504; the SPA already routes them away.

---

### D-2. Lock-order inversion between sidecar writers and `lock()`

**Where:** `daemon/src/vault/state.rs:862-869` (`lock`) vs `state.rs:313-329` (`change_password_inner`), `state.rs:436-454` (`add_passkey_to_sidecar`), `state.rs:457-461` (`update_login_policy`), and `state.rs:359-392` (`write_header` which acquires `vmk.read()` on line 362).

**Lock orders:**

| Function | Acquires |
|---|---|
| `lock()` | `vmk.write()` → `db.lock()` → `vault_uuid.lock()` → `wipe_ticket.lock()` → `lockout_map.lock()` |
| `change_password_inner` | `db.lock()` → `vmk.read()` (in `write_header`) → `vmk.write()` |
| `add_passkey_to_sidecar` | `db.lock()` → `vmk.read()` (in `write_header`) |
| `update_login_policy` | `db.lock()` → `vmk.read()` (in `write_header`) |

**Scenario (AB-BA deadlock):**

1. Thread A — `RegisterFido2` handler. Acquires `db.lock()` (the `_guard` at `state.rs:436`). About to call `write_header` which needs `vmk.read()`.
2. Thread B — the idle-lock ticker (`socket.rs:50-58`) wakes at the 60-second tick, calls `state.lock()`. Acquires `vmk.write()`. Tries to acquire `db.lock()` — blocked on A.
3. Thread A — tries to acquire `vmk.read()` — blocked on B's `vmk.write()` (RwLock: writers block readers).
4. Deadlock.

`std::sync::RwLock` does **not** queue writers fairly across readers in Rust's default implementation, so once a writer is queued, subsequent readers also block (writer-preferring). This guarantees the deadlock even without further contention.

**Impact:** Under multi-threaded tokio (now confirmed default), the daemon will lock up under a relatively benign sequence — passkey enrollment that happens to cross the 60-second idle-lock boundary, or admin-initiated `Lock` issued during a `UpdateLoginPolicy`. The 120 s `DISPATCH_DEADLINE_SECS` masks it from one client, but the inner task remains wedged, leaking thread and lock state on each occurrence.

**Fix idea:** Pick a single lock order across the codebase. The natural choice is `db → vmk` everywhere (it matches the more common direction). Refactor `lock()` to acquire in `db → vmk` order. Or: make `write_header` not require `vmk.read()` (it currently only needs the VMK to compute the HMAC — pass the VMK in as a parameter from the caller, who already has it).

**Realism:** Inevitable on a long-running daemon with passkey users.

---

### C-1′. Duress amplification: rate-limit bypass + non-distinguishing 200

**Where:** `auth.js:1100-1122`, `auth.js:1115,1117,1120`, `web/src/pages/Login.tsx:585-601`.

**What changed:**
```js
// auth.js:1107
const duressArmed = !!(u && u.duressEnforce && u.duressEnforce.armed);

// auth.js:1115
if (!duressArmed) {
  if (!checkAccountRate(emailHash))  return res.status(200).json({ ok: false, error: 'account_locked' });
  if (!checkLoginRate(getClientIp(req))) return res.status(200).json({ ok: false, error: 'too_many_requests' });
}
```

The intent (per the inline comment) is that the duress budget (3-20 attempts) IS the cap, so lockout would block the wipe path. The unintended consequences:

1. **Concurrent attackers have zero friction** — no rate-limit pushback, no exponential back-off, no 30/60/120/300/600 s lockout schedule. Combined with C-1 below (the counter race that lets `maxAttempts` concurrent attempts burn one slot), the wipe threshold is functionally never reached.
2. **HTTP 200 for lockouts** — `Login.tsx:585-601` accepts either `res.status === 429` OR `data.error in {account_locked, mfa_locked, too_many_requests}` to detect lockout. But duress-armed accounts never hit the lockout branch at all, so this is moot for them. The 200-not-429 change does work for non-armed accounts. *Not a race per se* but a security-relevant policy shift.
3. **No DoS cap on Argon2id evaluations for duress-armed accounts**: an attacker can submit unlimited concurrent password guesses, each spending ~6-8 s of CPU on the server's Argon2id verify. Even though the eventual wipe is the budget, the wipe doesn't fire (per C-1), so the attacker can sustain DoS indefinitely.

**Impact:** The hardened brute-force protection is intentionally disabled for duress-armed accounts, and the duress counter that's supposed to replace it doesn't increment monotonically under concurrency.

**Fix idea:** Keep rate-limiting active for duress-armed accounts — duress should be *in addition to*, not *instead of*, lockout. Add a separate "blocked by lockout AND duress armed → return special code that still costs an Argon2id evaluation but doesn't increment duress" path so the lockout doesn't strand the wipe.

---

### C-1. Duress failure counter race (lost increments)

**Where:** `auth.js:1093-1203` (login handler), `Login.tsx:461-470` (client-side intercept), `securityModes.ts:488-505` (client-side counter).

**Scenario (server side, current code):**

```js
const users = loadUsers();                        // line 1105
const u = users.find(x => x.emailHash === emailHash);
...
let authenticated = await verifyPassword(...);    // line 1125 — 6-8 s Argon2id
...
if (duressArmed) {                                // line 1171
  const prev = Number(u.duressFailureCount) || 0; // u is the OLD snapshot
  const next = prev + 1;
  if (next >= max) { duressWipe = true; performServerWipe(u.id); }
  else {
    const uIdx = users.findIndex(x => x.id === u.id);
    users[uIdx].duressFailureCount = next;
    saveUsers(users);                             // line 1184 — saves STALE users array
  }
}
```

Two concurrent wrong-password POSTs both:
- Load `users` with `duressFailureCount = N`.
- Await `verifyPassword` (different libuv worker threads).
- Compute `prev = N`, `next = N + 1`.
- `saveUsers(users)` with `duressFailureCount = N + 1`.

Net effect: 2 failed attempts but counter only increments by 1. With `maxAttempts = 3`, 6 concurrent requests still don't fire the wipe.

**Impact:** Duress wipe threshold is bypassable by parallelism. Combined with C-1′ (no rate-limit pushback), the wipe is functionally defeated. The user enabled it; the server says it's enforced; it isn't.

**Fix idea:** Wrap the entire `loadUsers → check duress → mutate → saveUsers` flow in `proper-lockfile` on `users.enc` (same pattern as `withMfaPendingLock` in `auth.js:220-244`). Or refactor `duressFailureCount` to a per-user file with its own lock, or use an atomic counter file.

**Realism:** Trivially scriptable — `Promise.all([fetch('/api/auth/login', ...), ...])`. No auth needed.

---

### C-4. Opportunistic password rehash race (silent clobber)

**Where:** `auth.js:1149-1154`.

```js
if (authenticated && u && u.passwordHash && !u.passwordHash.startsWith('$argon2id$')) {
  u.passwordHash = await hashPassword(password);   // ~6-8 s
  u.salt = null;
  saveUsers(users);
}
```

`users` was loaded before `await verifyPassword`. The rehash adds another `await hashPassword`. Concurrent requests that mutate other fields on `users` (duress counter, sessions, mfaEnforce, recovery key) during this window get clobbered when this saveUsers fires with the stale array.

**Impact:** Any state mutation during the rehash window is silently undone.

**Fix idea:** Defer rehash to a background queue, OR re-load + merge under a lock just before saving.

---

### C-9. Browser `keyStore.v2Pending` read-after-write race

**Where:** `web/src/crypto/keystore.ts:18`, `web/src/pages/Login.tsx:512,706`, `web/src/utils/localCrypto.ts:109`.

`keyStore.v2Pending = browserMasterPromise.then(...)` assigns a long-running promise. Concurrent `writeEncryptedLocal()` awaits it. If a write fires after the assignment but before `setV2Salt()` completes inside the promise, the v2 path silently falls back to v1.

**Impact:** Data intended for v2 keys is encrypted under v1 instead. Recoverable by the v1 fallback at `localCrypto.ts:153`, but the cryptographic invariant ("v2 once available, never v1") is broken.

**Fix idea:** `writeEncryptedLocal` should wait for both `v2Pending` AND a "salt-is-set" predicate, or hard-fail rather than silently fall back when v2 was expected.

---

### C-10. `publishCryptoSaltIfNeeded` fire-and-forget in daemon path

**Where:** `web/src/pages/Login.tsx:345`.

The daemon-mode `publishCryptoSaltIfNeeded` call runs without `await`. User logs out + clears site data immediately after login → server never received the salt → next login generates a new random salt → previously-written vault data is undecryptable.

**Fix idea:** `await` it, matching the server-mode behaviour at line 354.

---

### C-13. Recovery-key rotation race

**Where:** `auth.js:1310-1347`.

```js
const users = loadUsers();
...
const verified = await verifyPassword(u.passwordHash, password, u.salt);
...
const hash = await hashPassword(recoveryKey);
users[uIndex].recoveryKeyHash = hash;
...
saveUsers(users);
```

Two concurrent `POST /api/auth/recovery-key` (form double-submit, retry-races-original) both load, both await, both save. Last write wins.

**Impact:** User sees recovery key A; server stores hash of recovery key B → account un-recoverable.

**Fix idea:** Lock `users.enc` for the load-verify-hash-save sequence. Add idempotency-key on the request body to dedupe retries.

---

### C-14. Session revocation race (entries reappear)

**Where:** `auth.js:1417-1420`.

```js
app.post('/api/auth/sessions/revoke-others', authMiddleware, requireAuth, requireCsrf, (req, res) => {
  const list = loadSessions(req.user.id).filter(s => s.jti === req.user.jti);
  saveSessions(req.user.id, list);
  res.json({ ok: true });
});
```

Concurrent `recordSession()` from an active session can land between the filter and the save (or after the save with the writer holding stale state), causing the revoked session to re-appear.

**Fix idea:** Per-user sessions-file lock; OR a monotonic "revocation epoch" on the user record — `recordSession` only writes if epoch matches the epoch at session issuance.

---

### C-15. Password change vs concurrent login (session re-creation)

**Where:** `auth.js:1378-1404`.

```js
saveUsers(users);
saveSessions(req.user.id, []);  // invalidate all old sessions
```

Concurrent authenticated request from device B can call `recordSession()` after the wipe — old session UUID survives in the file. Same shape as C-14.

**Fix idea:** Revocation epoch as above.

---

## High Findings

### H-1. `/api/auth/crypto-salt` clobber

**Where:** `auth.js:1077-1090`. Two concurrent calls can regress `cryptoSalt` to a previous value. **Fix:** lock `users.enc` for load-check-then-set.

### H-2. `loginHints` sync clobber

**Where:** `auth.js` PUT `/api/auth/login-hints`. Concurrent writes overwrite each other's hints. **Fix:** same lock pattern.

### H-3. `mfaEnforce` write clobber

**Where:** `auth.js:1611-1638`. Concurrent `PUT /api/vault/mfa` overwrites the TOTP secret or enforce flags. **Fix:** lock + version field.

### H-4. Daemon session touch / idle-timer TOCTOU

**Where:** `daemon/src/ipc/socket.rs:50-58` (idle ticker) + `state.rs:337-338` (`touch`). Idle timer reads `last_activity` and locks the vault while a slow handler (8 s Argon2id) is mid-flight. Handler completes, `touch()` runs after the vault is already locked → subsequent crypto calls operate on zeroed VMK. **Fix:** generation counter on `touch`; idle-lock verifies generation matches before zeroing.

### H-6. Browser duress double-submit guard incomplete

**Where:** `Login.tsx:447-455`. The `if (loading) return;` guard reads from `useState`, which is subject to React batching. Pressing Enter twice rapidly before `setLoading(true)` flushes runs the handler twice and triggers C-1 client-side. **Fix:** `useRef`-backed in-flight flag.

### H-7. `getDuressModeConfigFull` server-mirror rollback (refreshed)

**Where:** `securityModes.ts:69-107`. When server-session is active, this fetches `/api/vault/duress-config` and **overwrites** local `duress_mode_config` + `_sentinel` from the server's copy. Two-tab scenario: tab A decrements local counter, tab B's `getDuressModeConfigFull()` fetches a slightly-stale server copy and overwrites tab A's freshly-decremented `attemptsRemaining`. With C-1 already losing increments on the server side, this multiplies the bypass surface.

**Fix:** never fetch from the server after the first hydrate-on-login. Or: include a monotonic version number and only overwrite when server version is strictly newer.

### H-8. Cross-tab localStorage RMW race

**Where:** `localCrypto.ts:108-179`. Multi-step "write blob then write sentinel" sequences observable in inconsistent states. Affects `mfa_config` + `mfa_config_plain`, `duress_mode_config` + sentinel, `_tm_cfg`. **Fix:** sentinel-after-blob is OK; readers must tolerate "blob present, sentinel missing" and re-read.

### H-9. Quick Unlock + password login race

**Where:** `Login.tsx:40-60` + `Login.tsx:447`. User starts biometric, then types password and submits. Two unlock RPCs queue on the daemon WS. If biometric times out, the WS tears down and orphans the password request. **Fix:** disable Quick Unlock button when password field has content; cancel one on the other's start.

### H-10. Emergency-request append race

**Where:** `auth.js:1898-1908`.

```js
const requests = readEncryptedFile(emergencyRequestsPath(...), ...);
requests.push(newReq);
writeEncryptedFile(emergencyRequestsPath(...), ..., requests);
```

Two concurrent emergency-access POSTs for the same account both read, both append, write — second clobbers first. Legitimate access requests silently dropped. **Fix:** lock the emergency-requests file.

### H-11. Share single-view flag race

**Where:** `auth.js:1789-1801`. Two concurrent `GET /api/share/:shareId` for a single-view share — the lock at line 1780 serializes them, BUT `record` is read **before** the lock acquisition window opens for the next caller. Actually the code is structured correctly here: lock → re-check existsSync → read record → check viewed → write tmp+rename inside the same lock scope (lines 1780-1802). **Re-evaluated: not a race after current rewrite. Keeping as informational; close on next audit if confirmed by trace.**

### H-12. Audit event flush race

**Where:** `auth.js:874-882` + `818-831`. `_auditQueue` is pushed without lock; `flushAuditQueue()` runs concurrently. **Impact:** events lost or duplicated. **Fix:** swap the queue atomically (`const drained = _auditQueue.splice(0)`), flush the drained copy.

### H-13. TOTP replay window race

**Where:** `auth.js:334-352`. `verifyTotpCode` does `periods.has(period) → ... → periods.add(period)`. Two concurrent verifications can both observe `has === false` and both add. **Actually re-checked**: with no `await` between `has` and `add` (both are sync `Set` ops), and the only `await` being `TOTP.generate` which happens BEFORE the `has` check, this is safe within a single tick. Two concurrent handlers serialize on the JS event loop between their `has`/`add` pairs. **Reclassifying to LOW.**

### H-14. `performServerWipe` racing concurrent `saveUsers` *(NEW)*

**Where:** `auth.js:1950-1958`.

```js
function performServerWipe(userId) {
  const dir = userVaultDir(userId);
  if (existsSync(dir)) { secureOverwriteDir(dir); rmSync(dir, { recursive: true, force: true }); }
  const remaining = loadUsers().filter(x => x.id !== userId);
  saveUsers(remaining);
}
```

A concurrent `/api/auth/login` failure-path handler is mid-`saveUsers(users)` with its own `users` array (which still contains the wiping user). If their `saveUsers` lands AFTER `performServerWipe`'s, the user record is re-created. The wipe is incomplete: vault dir gone, but user record present. On next login this account succeeds (no record-based reject), but vault data is missing → confusing UI state.

**Fix:** lock `users.enc` for the entire `performServerWipe`. Also: the load → filter → save here is itself an RMW that can race against any other `saveUsers` caller, so once lockfile is in place this fixes itself.

### H-15. `disarmDuressMode` local↔server divergence *(NEW)*

**Where:** `securityModes.ts:404-439`.

```js
localStorage.setItem(DURESS_KEY, noise);
localStorage.removeItem(DURESS_KEY);
localStorage.setItem(DURESS_KEY + '_sentinel', noise);
localStorage.removeItem(DURESS_KEY + '_sentinel');
if (hasServerSessionCookie()) {
  ...
  fetch('/api/vault/duress-config', { method: 'DELETE', ... });
  ...
}
try { await syncDuressEnforce(false, 0); } catch (e) { console.warn(...); }
```

Local wipe happens FIRST, then server. If the user re-arms in a second tab before `syncDuressEnforce(false)` lands, the second tab's arm-on-server can be undone by the first tab's disarm-on-server arriving later. Net state: server "disarmed", local-tab-2 "armed" — duress wipe will never fire because the server says it's not armed.

The catch-and-log of `syncDuressEnforce` failure (`console.warn` only) also means a network failure leaves the server side armed with stale `maxAttempts` while the user UI says "disarmed" → unexpected wipe on next concurrent attacker session.

**Fix:** Server first, local second. Or two-phase commit: stage local-pending, sync server, then promote local-pending. Surface sync failures to the UI (same as armDuressMode does at line 401).

### H-16. `VaultContext.reloadLocal` travel-config in-flight stale read *(NEW)*

**Where:** `web/src/context/VaultContext.tsx:336-348`.

```ts
let travel = getTravelModeConfig();
if (hasServerSession()) {
  try { travel = await getTravelModeConfigAsync(); } catch {}
}
if (travel.active) {
  if (f !== null) {
    f = f.filter(folder => !travel.hiddenFolderIds.includes(folder.id));
  }
}
```

`getTravelModeConfigAsync` does a server fetch. If the user enables or disables travel mode in another tab during this in-flight fetch, the filter applied to `f` is based on stale config. UI shows hidden folders that should be hidden, or hides folders that should be visible.

**Fix:** Hydrate travel config once on login (before any vault reads), not on every `reloadLocal`. Or: version-stamp travel config and re-filter when version changes.

### H-17. Server-authoritative duress / 200-not-429 race surface *(NEW)*

**Where:** `auth.js:1117,1120` + `Login.tsx:589-601`.

For non-armed accounts, lockout returns HTTP 200 with `data.error = 'too_many_requests'` (or `'account_locked'`). The browser distinguishes by parsing the JSON body. If a body parse fails (truncated response, MITM), the code falls through to the "wrong password" branch and increments the client-side `recordFailedLoginAttempt()` counter — eventually triggering the local-only duress wipe even though the server never authenticated against a wrong password.

The newly-added `RATE_LIMIT_CODES` set in `Login.tsx:585` is the correct mitigation but depends on the body being parseable. **Fix:** add an explicit X-Rate-Limited header (server-side) and check the header before the body, so a truncated/invalid body still takes the lockout branch.

---

## Medium Findings

### M-1. MFA token consumption race

**Where:** `auth.js:309-317`. `withMfaPendingLock` protects the file, but the `data.tokens[hash]` check inside the callback must be fully synchronous (no awaits between `get` and `delete`). Currently it is — confirm in code review.

### M-2. Daemon idle-timeout TOCTOU on unlock

**Where:** `daemon/src/ipc/socket.rs:50-58`, `state.rs:680-698`. Idle timer can lock the vault between the `check_unlock_lockout` and the just-completed `unlock_existing` flow. **Fix:** the recent `self.touch()` added in `unlock()` (line 693) helps but doesn't fully close the window. Generation-counter on `touch` would.

### M-3. Daemon lockout-map memory leak

**Where:** `state.rs:202-210`. Failed-unlock entries pruned only on next attempt. Idle attackers leave entries forever. **Fix:** periodic background prune (pattern already exists at line 145-146 for challenges).

### M-4. Travel Mode enable/disable atomicity

**Where:** `securityModes.ts:589-648,650-745`. `enableTravelMode` writes ciphertext envelope, then config, then server mirror — crash between leaves orphaned ciphertext (and now orphaned server-side state too with the new mirror endpoints). **Fix:** pending sentinel → envelope → promote pattern.

### M-5. `saveDuressModeConfig` local vs server mirror divergence

**Where:** `securityModes.ts:116-152`. Local plaintext write commits, server fetch fails silently — next-device login sees stale state. **Fix:** surface mirror failures to the UI (you did this for arm/disarm via DuressSyncError; extend to `saveDuressModeConfig` itself).

### M-6. `demoKeyAvailable` event handler idempotence

**Where:** `Login.tsx:544,732` + `VaultContext.tsx`. Both daemon and server login paths dispatch the event; concurrent dispatches cause `reloadLocal()` to fire twice, racing on `setFolders` / `setCredentials`. **Fix:** debounce the handler, or use a monotonic rev counter.

### M-7. Daemon `request` timeout queue race

**Where:** `daemonClient.ts:213-247`. On timeout, `ws.close()` is initiated; `onclose` drains the queue asynchronously. A new request enqueued in the window between `close()` call and `onclose` event fires might:
- `this.#queue.push(...)` succeed.
- `this.#ws!.send(...)` succeed (WS in CLOSING state may or may not throw depending on implementation).
- onclose drains and rejects the pending — but the daemon may have already processed the request.
- The daemon's eventual response arrives, finds an empty queue (line 150 `if (!next) return;`), silently dropped.

Net effect: client thinks request failed; server actually executed it.

**Fix:** state-machine the connection (`disconnected | connecting | open | closing`). Reject enqueues in `closing` and `disconnected` synchronously.

### M-8. Daemon passkey sign-count update race (reclassified from C-6)

**Where:** `daemon/src/vault/state.rs:579-588`.

```rust
if let Some(new_count) = updated_sign_count {
    if let Ok(mut fresh_header) = self.read_header() {
        if let Some(e) = fresh_header.passkey_credentials.iter_mut()
            .find(|e| e.credential_id_hex == cid_hex)
        {
            e.sign_count = new_count;
            let _ = self.write_header(&fresh_header);   // NOT under db.lock!
        }
    }
}
```

`add_passkey_to_sidecar` (line 436) and `update_login_policy` (line 457) DO hold `self.db.lock()` across the read-modify-write. This path does not. Concurrent `RegisterFido2` and passkey-unlock can:
- Lose a freshly-added passkey credential when the sign-count writer clobbers the sidecar with its older snapshot.
- Lose the sign-count increment when the register writer's `write_header` lands after.

**Impact:** Cloned-authenticator detection (H-16 in the daemon's own audit) weakened — a cloned authenticator can perform parallel assertions and both succeed.

**Fix:** wrap the sign-count block in `let _guard = self.db.lock().unwrap();` to match the other sidecar writers.

### M-9. WS rate-limiter race (`server.js`)

**Where:** `web/server.js`. Per-IP WS message limiter uses read-modify-write on a Map entry. Burst of concurrent messages can spike count above cap briefly. **Fix:** single-expression atomic update (the auth.js per-IP limiter at line 106-118 already uses this pattern — port it).

### M-10. Daemon `write_header` tmp-filename collision

**Where:** `daemon/src/vault/state.rs:377`. Two concurrent `write_header` calls both write `vault.db.meta.tmp` then rename. Linux rename is atomic per call, but if both writes target the same tmp path then rename, the second one's content wins entirely — the first's diff is lost ("blind write" race). **Fix:** unique tmp names (PID/UUID suffix) + wrapping lock to serialize.

### M-11. Settings.tsx async hydration races

**Where:** `web/src/pages/Settings.tsx` — `useEffect`s that hydrate Travel + Duress config. If the user mutates either while hydration is in flight, the hydration write overwrites the user's edit. **Fix:** confirm the `cancelled` flag pattern is in place; test under fast user actions.

---

## Low Findings

### L-1. `resetLoginAttempts` from two tabs

**Where:** `Login.tsx:343,353`. Both tabs reset on successful login — extra I/O, no correctness issue.

### L-2. Cookie timing on `hasServerSession()`

**Where:** `VaultContext.tsx:68-71`, `Login.tsx:122`. Brief window after fetch returns and before cookie jar updates where `hasServerSession()` returns false. **Fix:** check `X-Vault-Salt` response header or explicit body flag instead of polling `document.cookie`.

### L-3. TOTP replay (reclassified from H-13)

**Where:** `auth.js:334-352`. Re-verified: `Set.has` / `Set.add` sequence is fully synchronous inside the handler; Node's event loop serializes between handlers. Safe.

### L-4. `_pwd_lks` vs `_lk_salt` re-sync on every login

**Where:** `Login.tsx:639-660`. Cosmetic — both tabs writing identical content is harmless.

---

## Pattern Analysis

### Pattern A: `load → mutate → save` without lock *(server-side, Node)*

**Affected:** C-1, C-4, C-13, C-14, C-15, H-1, H-2, H-3, H-10, H-14.

Same root cause as before: every `await` is a yield point. `users.enc` and per-user vault blobs are written via tmp+rename (atomic on Linux) but **not lock-coordinated**. The recent server-side duress flag is a new instance of this pattern, not a fix.

**Fix:** Extend the `withMfaPendingLock` (auth.js:220-244) pattern to a generic `withUsersLock` helper and refactor every `loadUsers() ... saveUsers(users)` site. ~50 line change to introduce, then a mechanical refactor.

### Pattern B: Rust Mutex released between check and write

**Affected:** M-8, M-10.

Mostly mitigated by the existing `_guard = self.db.lock()` pattern on sidecar writers. M-8 is the one remaining instance. M-10 is the unique-tmp-name issue.

### Pattern C: Async state race in React closures

**Affected:** C-9, H-6, H-7, H-16, M-6.

`useState` setters are batched/async. `if (loading) return` checks stale closure capture. The new H-16 (travel config in-flight stale) and refreshed H-7 (duress server-mirror clobber) are new instances of this pattern from the recent server-mirror work.

**Fix:** `useRef` for in-flight flags; version-stamped state for hydration; debounce server-mirror reads.

### Pattern D: WebSocket FIFO assumption violated under reconnect

**Affected:** M-7.

H-5 (double-open) is now resolved. M-7 (in-flight queue drain on timeout) remains. Refactor `DaemonClient` to a state machine with `closing` state that rejects enqueues synchronously.

### Pattern E: Cross-tab inconsistency

**Affected:** H-7, H-8, H-15, H-16, M-6.

`localStorage` is shared but `storage` events don't fire in the writing tab. Each tab has its own React state. The new server-mirror endpoints for duress/travel make this worse — multi-tab edits race against the server's view.

**Fix:** subscribe to `storage` events in each tab; treat the server mirror as a CRDT-ish surface; surface conflicts to the user.

### NEW Pattern F: Lock-order inversion across vmk ↔ db *(Rust)*

**Affected:** D-1, D-2.

Different code paths acquire `vmk` and `db` in different orders. Under multi-threaded tokio this is a deadlock surface. The `lock()` function takes vmk-then-db; everything else takes db-then-vmk.

**Fix:** Pick one global lock order (recommend `db → vmk` since most code already follows this) and refactor `lock()` to match. Audit every Mutex/RwLock acquisition for ordering compliance.

---

## Out-of-scope but observed during audit

- **`web/src/pages/AddCredential.tsx:1825`** ends with `1;\n}` after the final `}`. **`web/src/pages/Dashboard.tsx:134`** ends with `);\n}`. Both files will not parse. Not race conditions — but they will break the build, which means even this audit's findings can't be verified by running tests until those are fixed.
- **Cloudflare sync** (`daemon/src/sync/cloudflare.rs`) — not audited. If active in deployment, the local↔cloud merge needs its own concurrency audit.
- **Fuzz targets** (`daemon/fuzz/`) — not audited; out of scope.

---

## Realism / Reachability

| Finding | Trigger | Realistic? |
|---|---|---|
| D-1 (wipe deadlock) | Any successful wipe attempt | **Yes — already broken in production** |
| D-2 (lock-order inversion) | Passkey enrollment crossing idle-lock tick | Yes — benign user actions, long-running daemon |
| C-1 (duress counter) | 2+ wrong-password POSTs in parallel | Yes — trivial script, no auth |
| C-1′ (rate-limit bypass) | Same — duress-armed accounts | Yes |
| C-4 (rehash clobber) | Race timed to the ~8 s rehash window | Sometimes |
| C-9 (`v2Pending`) | Fast user action during login | Sometimes |
| C-10 (salt publish) | Log out / clear cache in <100 ms post-login | Possible |
| C-13 (recovery-key) | User double-submits form | Common UX bug |
| C-14 / C-15 (session revoke) | Active attacker holding session during revoke | Targeted |
| H-7 / H-16 (server-mirror rollback) | Two-tab usage | Common |
| H-14 (wipe vs save) | Concurrent login during a wipe | Targeted |
| H-15 (disarm divergence) | Disarm during weak network | Common |
| M-7 (timeout queue) | Daemon timeout under load | Sometimes |
| M-8 (sign-count race) | Concurrent passkey unlock + register | Rare but reachable |

**Prioritisation recommendation:** D-1 first (it nullifies the headline duress feature). Then C-1 + C-1′ together (one `proper-lockfile` wrapper closes both). Then D-2 (lock order). Then C-13 and the rest of Pattern A in one batch.

---

## What to do next

1. **Fix D-1** before anything else — the daemon doesn't actually wipe. Smallest change: pull the ticket out of `with_vmk` before calling `forensic_wipe`.
2. **Write a `withUsersLock(fn)` helper** in `auth.js` (analogous to `withMfaPendingLock`) and mechanically refactor every `loadUsers() ... saveUsers(users)` site to use it. This closes C-1, C-1′, C-4, C-13, C-14, C-15, H-1, H-2, H-3, H-14 in one pass.
3. **Audit lock order** in `daemon/src/vault/state.rs`. Document the canonical order (recommend `db → vmk → vault_uuid → wipe_ticket → lockout_map → sessions`) and rewrite `lock()` to match.
4. **Fix M-8** with a `let _guard = self.db.lock();` block around the sign-count write.
5. **Fix the two SPA syntax errors** in `AddCredential.tsx` and `Dashboard.tsx` so the rest of the audit's findings can be verified end-to-end.
6. **Add concurrent regression tests** — `Promise.all([fetch(...), fetch(...)])` for each Critical, asserting final state. The existing `e2e/duress-wipe-trigger.spec.ts` only covers sequential failures and would not have caught any of the C-1 family.

---

## Not Confirmed / Notes carried from prior audit

- `ecosystem.config.cjs` sets `instances: 1` (confirmed: PM2 single-worker). The in-memory `_loginRateLimiter`, `_accountLockout`, `_mfaFailedAttempts`, `_usedTotpPeriods` Maps are therefore globally consistent. If this is ever bumped to `> 1`, every Map becomes per-worker and a CI check should guard against the change.
- Daemon tokio scheduler: **confirmed multi-thread** (`#[tokio::main]` default + `features=["full"]`). This was the prior audit's open question; now closed unfavourably.
- `daemon/fuzz/` and `daemon/src/sync/cloudflare.rs` remain unaudited.
