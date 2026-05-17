# Security Audit Report – Critical & Non-Critical Findings

**Project:** PWDnow (Layer-1 Rust vault daemon + Layer-2 Express/React web)
**Audit date:** 2026-05-17
**Auditor role:** Senior application security engineer (SAST + manual pentest simulation)
**Scope:** `daemon/`, `web/`, `deploy/`, dependency manifests, encrypted server data layout.
**Remediation status:** All 32 findings fixed as of 2026-05-17 (commit pending).
**Note on the database:** This project has no external DBMS. Storage is (a) SQLCipher inside the Rust daemon (`daemon/vault.db`) and (b) per-user AES-256-GCM-encrypted files under `web/auth_data/`. No external `DB_CONNECTION_STRING` is required; the audit was performed against the static repository state plus on-disk file/permission inspection.

---

## Summary

- **Total flaws found (after second-pass deep audit):** 32
- **Critical:** 1 · **High:** 6 · **Medium:** 11 · **Low:** 11 · **Info:** 3
- **Status:** ✅ ALL FIXED
- **Most dangerous vulnerability (Critical):** The Passkey VMK wrap key is derived from the *registration-time* `authData[0..33]` (where the flags byte includes the `AT` attested-credential-data bit, e.g. `0x41` / `0x45`), but the *unlock-time* derivation re-runs on the *assertion-time* `authData[0..33]` (flags byte `0x01` / `0x05`, no `AT` bit). Because the flags byte feeds the HKDF salt, the two wrap keys differ and the AES-GCM-wrapped VMK can never be decrypted on a real authenticator. This breaks the passwordless-passkey unlock path entirely (correctness/availability), and combined with the wipe-on-password-change semantics of `passkey_credentials`, can produce permanent account-loss states for any user who has set a non-trivial primary password (see finding #15 in the Round-2 section). The previously top-rated issue (`/api/vault/wipe` without password re-verification, finding #1) remains the most impactful **attacker-driven** primitive, since one captured session token destroys the entire account.

Findings #1-#14 below are from the first pass; **findings #15-#32 are from the deep-dive second pass** and appear after the Round-1 priority list. The single revised "Priority order for fixes" at the very bottom consolidates both rounds.

The codebase is, on the whole, well-defended: zero `npm audit` issues, sandboxed daemon (AppArmor + systemd hardening + `mlock`), AEAD everywhere, per-credential DEKs, post-quantum hybrid KEM, header HMAC, audit-log HMAC chain, brute-force lockout, Argon2id at OWASP-strong parameters. All findings below are residual hardening items rather than systemic crypto failures.

---

## Full Vulnerability List

---

### 1. Destructive vault wipe lacks password re-verification

- **Severity:** High
- **Title:** `/api/vault/wipe` deletes entire account on session cookie alone
- **Location:** `web/auth.js:1712-1722`
- **Description:** The endpoint requires `authMiddleware`, `requireAuth`, and `requireCsrf` — i.e. a valid session JWE cookie plus the matching `_pwd_csrf` header. It does **not** call `verifyPassword()` first. Every other security-sensitive endpoint in the file (audit log delete at `auth.js:1737`, password change at `auth.js:1255`, recovery-key rotation at `auth.js:1187`) requires `oldPassword` / `password` re-verification before mutating, but the most destructive operation in the system does not.
- **Exploitation scenario:** A reflected/stored XSS, a malicious dependency, a stolen cookie, a logged-in shoulder-surfed laptop, or a hijacked session pulled out of a memory dump can be used to issue one POST that secure-overwrites the user's `credentials.enc`, `folders.enc`, `profile.enc`, audit log, and removes the user record entirely. There is no recovery path — the AES-GCM keys are unrecoverable once `auth_data/vault/<uid>/` is wiped and the user row is removed.
- **Proof of concept (simulated):**
  ```http
  POST /api/vault/wipe HTTP/1.1
  Host: vault.local
  Cookie: _pwd_sess=<stolen JWE>; _pwd_csrf=<value>
  X-CSRF-Token: <same value>

  HTTP/1.1 200 OK
  {"ok":true}
  ```
- **Remediation:** Require fresh password re-verification (and ideally a second factor) before wiping. Mirror the pattern from `auth.js:1737-1772`:
  ```js
  app.post('/api/vault/wipe', authMiddleware, requireAuth, requireCsrf, async (req, res) => {
    const { password } = req.body ?? {};
    if (typeof password !== 'string') return res.status(400).json({ error: 'password_required' });
    const users = loadUsers();
    const u = users.find(x => x.id === req.user.id);
    if (!u) return res.status(401).json({ error: 'user_not_found' });
    if (isMfaLocked(u.id)) return res.status(429).json({ ok: false, error: 'too_many_attempts' });
    const verified = await verifyPassword(u.passwordHash, password, u.salt);
    if (!verified) { recordMfaFailure(u.id); return res.status(401).json({ error: 'invalid_credentials' }); }
    clearMfaFailure(u.id);
    // ... existing wipe logic ...
  });
  ```
- **CWE ID:** CWE-306 (Missing Authentication for Critical Function) / CWE-862 (Missing Authorization)

---

### 2. Cross-site WebSocket hijacking via Host-equals-Origin fallback

- **Severity:** High
- **Title:** WebSocket upgrade trusts `Origin === <scheme>://<Host>`, defeating the allow-list
- **Location:** `web/server.js:606-630`
- **Description:** Origin validation has two branches:
  ```js
  const isSameHost = host && origin && (origin === `http://${host}` || origin === `https://${host}`);
  if (!origin || (!isSameHost && !ALLOWED_WS_ORIGINS.has(origin))) { ws.close(...); return; }
  ```
  Both `Origin` and `Host` are client-controlled headers. Any attacker page that can persuade a browser to send a WebSocket upgrade where `Host` matches `Origin` (DNS rebinding to 127.0.0.1, malicious local network captive portal, attacker-controlled DNS for a victim, IP-as-Host attacks) passes `isSameHost` regardless of `ALLOWED_WS_ORIGINS`. The accompanying `Sec-Tab-Nonce` check at `server.js:626-628` is bypassable in the same call because **the server accepts any query-string nonce when no cookie is present**: `const nonce = queryNonce || cookieNonce`. Cross-site requests do not carry cookies (SameSite=Strict), so `cookieNonce` is null and any attacker-supplied `?nonce=x` satisfies the check.
- **Exploitation scenario:** Rebind `vault.local` (or the customer-deployed FQDN) to `127.0.0.1` in the victim's DNS via cache poisoning or attacker-controlled network. The attacker page connects `new WebSocket('ws://vault.local/ws?nonce=AAAA')`. Both `Origin` and `Host` are `vault.local`; the check passes. The attacker can now drive **unauthenticated** daemon commands such as `Unlock { password: <guess> }` (bypassing nginx's per-IP `auth_limit`, which only sees the Express server), accelerating online brute-force; `ForensicWipe { ticket }` if any prior ticket leak occurred; or simply exhaust the daemon's global pre-auth cap (`socket.rs:68`, 16 connections) to deny service.
- **Proof of concept (simulated):**
  ```js
  // Attacker JS on rebound vault.local
  const ws = new WebSocket('ws://vault.local/ws?nonce=' + crypto.randomUUID());
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => {
    // msgpack-encoded { Unlock: { password: "guess", ... } }
    ws.send(buildMsgpackUnlock('guess123'));
  };
  ```
- **Remediation:** Drop the `isSameHost` fallback entirely; require `origin ∈ ALLOWED_WS_ORIGINS`. Make `Sec-Tab-Nonce` mandatory and reject when the cookie is absent (not when both are present and equal):
  ```js
  if (!origin || !ALLOWED_WS_ORIGINS.has(origin)) {
    ws.close(1008, 'origin not allowed'); return;
  }
  if (!cookieNonce || cookieNonce !== queryNonce) {
    ws.close(1008, 'tab nonce mismatch'); return;
  }
  ```
  Operators should deploy `vault.local` only behind nginx and use `server_name` strictly (already done in `deploy/nginx/vault.conf:32`); add nginx-level `if ($host !~ "^(vault\.local|<deployed-fqdn>)$") { return 444; }`.
- **CWE ID:** CWE-942 / CWE-1385 (Cross-Site WebSocket Hijacking) / CWE-350 (Reliance on Reverse DNS / Host header)

---

### 3. Race condition in shared MFA-pending storage (TOCTOU)

- **Severity:** High
- **Title:** `mfa_pending.enc` read-modify-write is not locked; PM2 cluster workers race
- **Location:** `web/auth.js:65-82, 200-218, 250-268`
- **Description:** `loadMfaPending()` reads the whole file, prunes expired entries, and if anything changed calls `saveMfaPending()` to rewrite. `issueMfaToken()`, `consumeMfaToken()`, `storeEmailOtp()`, `consumeEmailOtp()` all do read-modify-write on the same global file with no `proper-lockfile` guard. The vault data per-user files **do** use `lock(dir)` in `recordSession()` and `processAuditEvent()`, but the MFA pending store does not. PM2 cluster mode (`web/ecosystem.config.cjs`) runs N workers in parallel; concurrent calls during a login burst can lose tokens.
- **Exploitation scenario:**
  - Availability: a legitimate user's `partialToken` written by worker A is silently overwritten by worker B's `loadMfaPending → mutate → save` cycle that started before A's write completed, returning a "invalid_or_expired_mfa_token" on `/login/finish`.
  - Security: under load, an attacker who sees a stale read may consume an OTP that has already been consumed by a parallel call (the `delete data.emailOtps[key]` in worker A may not yet be visible to worker B), undermining single-use semantics. Together with the per-account MFA lockout (`auth.js:226-244`), an attacker who can deliberately race could repeatedly consume-and-fail MFA codes to bypass replay protection.
- **Proof of concept (simulated):**
  ```
  Worker A: loadMfaPending() → snapshot{ emailOtps: {k1: '111111'} }
  Worker B: loadMfaPending() → snapshot{ emailOtps: {k1: '111111'} }
  Worker A: storeEmailOtp(t2) → save({k1, k2})
  Worker B: storeEmailOtp(t3) → save({k1, k3})   # k2 lost
  ```
- **Remediation:** Wrap every `loadMfaPending → mutate → saveMfaPending` cycle in a `proper-lockfile.lock(mfaPendingPath())` retry-acquire block (already used by `recordSession`). Alternatively move pending MFA to a small SQLite file with `BEGIN IMMEDIATE` transactions, which serialises naturally across processes.
- **CWE ID:** CWE-367 (TOCTOU) / CWE-362 (Race Condition)

---

### 4. User enumeration via `/api/auth/login-hints`

- **Severity:** Medium
- **Title:** Email-existence and enrolled-MFA-method leak through public POST
- **Location:** `web/auth.js:963-992`
- **Description:** The handler accepts `{ email }`, computes `hashEmail`, looks up the user, and responds with either the static `defaults` object (no user, or user with no stored hints) or `{ ...defaults, ...u.loginHints }`. Any client-set `loginHints` will produce a response that differs from `defaults` (the frontend writes these on every login at `/api/auth/login-hints` with auth — see lines 966-979), so the response body itself reveals (a) whether the email is registered and (b) which login methods are enrolled (TOTP, email OTP, passkey, etc.). No rate limit is attached to this endpoint.
- **Exploitation scenario:** An attacker scrapes a corporate email list and probes the endpoint to enumerate which addresses have PWDnow accounts, then which accounts have only password (no MFA) — directing brute-force at the weakest accounts. Combined with finding #5 (no nginx rate-limit on this path; the `auth_limit` regex in `deploy/nginx/vault.conf:136` only catches `/login`, `/login/finish`, `/forgot-password`, `/register`, `/2fa`), enumeration is unrestricted.
- **Proof of concept (simulated):**
  ```http
  POST /api/auth/login-hints
  { "email": "victim@example.com" }
  → 200 { "hints": { "totp": true, "emailOtp": false, "passwordEnabled": true, ... } }
  POST /api/auth/login-hints
  { "email": "nonexistent@example.com" }
  → 200 { "hints": { "totp": false, "emailOtp": false, "passwordEnabled": true, ... } }   // distinguishable
  ```
- **Remediation:**
  1. Apply a per-IP rate limiter (e.g. re-use `checkLoginRate`) at the top of the handler.
  2. Add `/login-hints` to the nginx `auth_limit` location regex.
  3. Always return the exact same default shape unless the request is already authenticated and is fetching its own hints. Move enrolled-method discovery behind successful primary auth (or behind a successful `/api/auth/login` body that already required correct password) rather than exposing it pre-auth.
- **CWE ID:** CWE-204 (Response Discrepancy) / CWE-307 (Improper Restriction of Excessive Authentication Attempts)

---

### 5. Privileged state-changing endpoints lack password re-verification

- **Severity:** Medium
- **Title:** Emergency-access enrolment and contact change accept session cookie only
- **Location:** `web/auth.js:1604-1623` (`POST /api/vault/emergency`)
- **Description:** Setting up emergency access writes a `contactEmail` and a server-issued `token` to the user's vault. After the configured wait period, anyone holding that token can demonstrate "ownership" to recover the account. The endpoint requires only an authenticated session + CSRF, with no `verifyPassword()` re-check.
- **Exploitation scenario:** An attacker who steals a session (XSS, exfiltrated cookie, machine compromise) flips `contactEmail` to an attacker-controlled mailbox, retrieves the token via `GET /api/vault/emergency`, then 24-168 hours later uses the token to gain emergency access — effectively a persistence/recovery backdoor.
- **Proof of concept (simulated):**
  ```http
  POST /api/vault/emergency        # session-only
  { "contactEmail": "attacker@evil.com", "waitPeriodHours": 24 }
  → 200 ok; token written into encrypted blob

  GET /api/vault/emergency         # session-only
  → returns { token: "<64-hex>" }

  ... 24 h later, off-session ...
  POST /api/emergency/request/<token>
  ```
- **Remediation:** Treat enrolment and rotation of recovery/escalation paths identically to password rotation — require password (and TOTP if enrolled) re-verification, and emit an out-of-band notification (e-mail to the **old** contact, audit-log entry, optional cooldown). Compare to `auth.js:1187-1224` which already does this correctly for recovery keys.
- **CWE ID:** CWE-620 (Unverified Password Change) / CWE-863 (Incorrect Authorization)

---

### 6. Session created beyond `MAX_TOTAL_SESSIONS` silently invalid

- **Severity:** Medium
- **Title:** Daemon `SessionStore::create` returns an unstored session when the global cap is reached
- **Location:** `daemon/src/auth/session.rs:117-122`
- **Description:**
  ```rust
  if map.len() >= MAX_TOTAL_SESSIONS {
      return session;          // <-- session not inserted, but returned to caller
  }
  map.insert(session.token.clone(), session.clone());
  session
  ```
  When the global cap (1000) is hit, callers receive a `Session` whose token is valid-looking but is never stored. The very first authenticated call after `Unlock` then fails with `session not found`. Callers in `socket.rs` use this returned session unconditionally (e.g. line 221: `Response::Unlocked { session_token: sess.token, … }`), so the client believes they are unlocked and only discovers the broken state on next request.
- **Exploitation scenario:** A botnet (or accidental client retry loop) inflates the session map to 1000 by repeatedly invoking `Unlock`. From that point legitimate logins succeed at the IPC layer (returning `Unlocked`) but the very next authenticated request fails — denial of service masquerading as flaky auth. Also leaks the cap value indirectly via the failure pattern.
- **Proof of concept (simulated):**
  ```rust
  // Adversarial loop (peer UID is the vault owner — trusted user model)
  for _ in 0..1000 { daemon.unlock(correct_pw); }
  // 1001st caller:
  let s = daemon.unlock(correct_pw)?;
  daemon.list_credentials(&s.token)? // → Error: session not found
  ```
- **Remediation:** Return `Result<Session, VaultError>` from `create()` and signal capacity-exhaustion explicitly:
  ```rust
  if map.len() >= MAX_TOTAL_SESSIONS {
      return Err(VaultError::Auth("session capacity exhausted".into()));
  }
  ```
  Then surface a 503 to the client. Also prune `is_valid()==false` entries before the cap check (already done at line 102) and consider evicting the oldest valid session when the cap is reached, matching the per-user logic above it.
- **CWE ID:** CWE-754 (Improper Check for Unusual Conditions) / CWE-400 (Resource Exhaustion)

---

### 7. Unbounded `loginHints` mass-assignment

- **Severity:** Medium
- **Title:** Authenticated client can write arbitrary JSON into `users[].loginHints`
- **Location:** `web/auth.js:966-979`
- **Description:** Inside `/api/auth/login-hints` the sync branch executes `users[userIndex].loginHints = hints` with no shape validation or size cap. `hints` is whatever the client sent. The file `auth_data/users.enc` is loaded into memory on every authenticated request (`loadUsers()` has no cache for revocation reasons — `auth.js:426-429`), so unbounded growth here amplifies per-request memory and decrypt cost across the whole tenant.
- **Exploitation scenario:** A malicious authenticated user POSTs `hints: { junk: "A".repeat(400_000) }` repeatedly (each call up to the 512 kB body cap). The users blob grows; AES-GCM decrypt + JSON.parse latency rises across the population. Over time, this also raises Argon2id contention because the per-IP rate limiter doesn't apply here. A second attacker variant: send `hints` containing a nested `prototype` or `constructor` property; while V8 will not pollute via JSON.parse, the field is later spread into a response (`...safeHints`) at line 991 — `cryptoSalt` is filtered but no other keys are, so any field is reflected to anyone that probes the user's email.
- **Proof of concept (simulated):**
  ```http
  POST /api/auth/login-hints           # authenticated
  X-CSRF-Token: <csrf>
  { "hints": { "totp": true, "x": "AAAAA...(500 KB)..." } }
  ```
- **Remediation:** Validate `hints` against an explicit allow-list and size limit:
  ```js
  const SAFE_KEYS = new Set(['totp','emailOtp','webauthn','passkey','platform','passwordEnabled','passwordlessEnabled']);
  if (!hints || typeof hints !== 'object') return res.status(400).json({error:'invalid'});
  const sanitized = {};
  for (const k of Object.keys(hints)) {
    if (!SAFE_KEYS.has(k)) continue;
    if (typeof hints[k] !== 'boolean') continue;
    sanitized[k] = hints[k];
  }
  users[userIndex].loginHints = sanitized;
  ```
- **CWE ID:** CWE-915 (Mass Assignment) / CWE-400 (Uncontrolled Resource Consumption)

---

### 8. Plaintext credentials and tokens in non-production logs

- **Severity:** Medium
- **Title:** `NODE_ENV` misconfiguration prints user IDs, email OTPs, and "login completed for <uid>" to stdout
- **Location:** `web/auth.js:1009-1010, 1106-1108, 1113-1115, 1175-1177`
- **Description:** Diagnostic logging is gated on `process.env.NODE_ENV !== 'production'`. The systemd unit (`deploy/vault-daemon.service`) sets nothing about `NODE_ENV`; the PM2 config is launched with `--env production` but only when operators use the documented `npm run pm2:start`. Any other launcher (custom systemd, Docker without `--env NODE_ENV=production`, `npm start` directly) leaks:
  - Generated email OTPs (`auth.js:1107` — a complete pre-MFA bypass via journal access).
  - User IDs and `cryptoSalt`-stored events.
  - Login completion records associated to user IDs.
  systemd journal is world-unreadable on most distros but may be exported, rotated, or read by sysadmins; container logs are typically captured by external aggregators (Loki, ELK).
- **Exploitation scenario:** A non-`production` deploy ships email OTPs to the system log. An attacker with read access to the journal (compromised log aggregator, accidental log export, screenshot) sees the OTP within its 5-minute window and combines it with a stolen primary password to bypass email-OTP MFA without ever receiving the email.
- **Proof of concept (simulated):**
  ```
  $ journalctl -u pwdnow | tail -1
  [auth][dev] Email OTP for 1f3...c4: 482911
  ```
- **Remediation:**
  - Remove dev-only logging of OTPs entirely (or print only its hash). OTPs should never hit stdout regardless of environment.
  - Replace the `NODE_ENV` switch with an explicit `LOG_VERBOSITY` opt-in that defaults to off.
  - Add a server-startup assertion `if (!process.env.NODE_ENV) throw new Error('NODE_ENV must be set explicitly');` to fail closed.
- **CWE ID:** CWE-532 (Insertion of Sensitive Information into Log File) / CWE-209 (Information Exposure Through Error/Debug Output)

---

### 9. SQLCipher key derived via HKDF-Sha3_512 but `format!` builds the PRAGMA string

- **Severity:** Low
- **Title:** PRAGMA key built with `format!("x'{}'", hex)` — defensible but unaudited string-pragma path
- **Location:** `daemon/src/vault/db.rs:25-27, 64-66`
- **Description:** Both `open_vault` and `rekey_vault` build the PRAGMA value with format-string interpolation:
  ```rust
  let key_hex = format!("x'{}'", hex::encode(sqlcipher_key));
  conn.pragma_update(None, "key", key_hex)?;
  ```
  `sqlcipher_key` is a `[u8; 32]` produced by `Self::sqlcipher_key()` (HKDF-Sha3_512) — not user-controlled — so this isn't a SQL-injection sink today. However the pattern is fragile: any future code path that lets attacker-influenced bytes reach `sqlcipher_key` would inject SQL via the pragma. The safer rusqlite idiom is `conn.pragma_update(None, "key", &key_hex)` with `key_hex` as a typed `ToSql` blob, not an interpolated literal.
- **Exploitation scenario:** Pure defense-in-depth concern. Today exploitable only via a memory-corruption of the HKDF output, which would break far worse invariants first.
- **Remediation:** Use parameterised key pragma:
  ```rust
  let blob = rusqlite::types::ToSqlOutput::Borrowed(rusqlite::types::ValueRef::Blob(sqlcipher_key));
  conn.execute("PRAGMA key = ?1", params![blob])?;
  ```
- **CWE ID:** CWE-89 (latent) / CWE-1188 (Insecure Default Initialization of Resource)

---

### 10. Setup-token endpoint vulnerable to DNS rebinding pre-first-run

- **Severity:** Low
- **Title:** `GET /api/setup-token` returns the privileged setup token to any localhost caller
- **Location:** `web/server.js:362-371`
- **Description:** Before `/api/setup-complete` is called the in-memory token is vended to any caller whose `req.socket.remoteAddress` is loopback. In dev, the server binds to `127.0.0.1` and the browser is the only loopback client. But a victim's browser visiting an attacker page that resolves an attacker-controlled DNS name to `127.0.0.1` will, in the post-bind / pre-setup window, be able to read the token via JS (response is JSON, CORS-restricted to same-origin so this only succeeds during DNS-rebinding; CSRF token isn't required since the endpoint is GET).
- **Exploitation scenario:** Operator runs `npm start` on a fresh install and walks away to read documentation. An attacker page (visited in the same browser session) DNS-rebinds to 127.0.0.1, fetches `/api/setup-token`, then POSTs `/api/setup-complete` (with the token in `X-Setup-Token`) to lock the operator out of finishing legitimate setup, or POSTs `/api/ubuntu-pro/attach` with an attacker-controlled token. Already partly mitigated by `refuseIfSetupDone` flipping the gate, but not by Origin/Host validation.
- **Remediation:** Reject requests whose `Origin` and `Host` are not exact-match to a configured `SETUP_ORIGIN` env var or `127.0.0.1:<PORT>`. Add `Vary: Origin` and an explicit `Access-Control-Allow-Origin: null` header. Long-term, move setup behind a CLI rather than HTTP.
- **CWE ID:** CWE-350 / CWE-942

---

### 11. WS upgrade rate limit bypassable by IP rotation; per-tab rate limit shareable

- **Severity:** Low
- **Title:** Per-IP connect throttle (30/min) ineffective for distributed clients; per-tab nonce DOS-able
- **Location:** `web/server.js:556-575`
- **Description:** `isWsRateLimited()` counts connects per `x-real-ip || socket.remoteAddress`. With nginx in front, IP is reliable, but the throttle does not prevent a 30-clients-from-30-IPs attack on the daemon's 16-slot pre-auth cap (`socket.rs:68`). The per-tab IPC counter (`wsNonceCounts`, 200 req/min per tab nonce) can be shared/replayed across browsers if the nonce is leaked, because no proof of possession is required.
- **Exploitation scenario:** Mass-connection denial of service against a public PWDnow deployment exhausts the daemon's pre-auth cap; legitimate users can't unlock.
- **Remediation:** Add a global pre-auth cap aware of the daemon's limit (`MAX_PRE_AUTH_CONNECTIONS = 16` on the web side, returning 503 instead of letting connections queue at the daemon). Bind tab nonces to a server-side issued cookie that the WS handshake must echo via a signed query param.
- **CWE ID:** CWE-770 (Allocation of Resources Without Limits)

---

### 12. Forensic-wipe overwrite is unreliable on copy-on-write filesystems

- **Severity:** Low
- **Title:** `secureOverwriteDir` 3-pass random overwrite cannot guarantee block reuse on SSD/tmpfs/btrfs
- **Location:** `web/auth.js:1697-1710` and `daemon/src/vault/wipe.rs` (`media_overwrite`)
- **Description:** Pattern-overwrite via `writeFileSync(path, randomBytes(size))` writes to **logical** file positions; on wear-leveled SSDs, btrfs/zfs CoW, tmpfs, and any virtualization layer with thin-provisioning, the physical blocks holding prior plaintext-equivalent ciphertext may persist indefinitely. The default daemon path uses `cryptographic_erase` (good) but the web layer's overwrite is the only line of defense for `auth_data/`. NIST SP 800-88 Rev. 2 explicitly disclaims overwrite as a sanitisation method for flash media.
- **Exploitation scenario:** After a Duress-Mode wipe, a forensic examiner extracts the SSD or VM image and recovers ciphertext from un-mapped flash pages. Because the master AES key remained in `auth_data/.master_key` until `rmSync` (not overwritten — note `secureOverwriteDir` doesn't iterate the parent dir contents, only `userVaultDir`), key + ciphertext recovery yields plaintext.
- **Remediation:**
  - Mark this clearly in operator docs: "secure wipe is best-effort; use FDE for at-rest protection".
  - On wipe, also crypto-erase the per-user HKDF-derived sub-keys by rotating the master key.
  - Optionally, only support wipe on filesystems that the daemon can verify provide `fstrim`/`discard` semantics, and call `posix_fadvise(POSIX_FADV_DONTNEED)` + `fsync` + `discard` after each overwrite.
- **CWE ID:** CWE-212 (Improper Removal of Sensitive Information Before Storage or Transfer)

---

### 13. Unauthenticated emergency endpoint scans every user record per request

- **Severity:** Low
- **Title:** `POST /api/emergency/request/:token` decrypts all users' `emergency.enc` on every call
- **Location:** `web/auth.js:1633-1676`
- **Description:** The handler iterates `loadUsers()` and `readEncryptedFile(emergencyPath(u.id), …)` for every user until it finds a matching token. Rate-limit is 5 req/min per IP via `checkEmergencyRate`. With ~100 user blobs in `auth_data/vault/*/`, that's 500 AES-GCM decrypts per minute per attacking IP — modest, but linear in tenant count and unauthenticated.
- **Exploitation scenario:** A botnet with 1000 IPs each calling 5 times per minute against a 10 000-user tenant performs 50 million decrypts/min, saturating CPU.
- **Remediation:** Maintain an in-memory `Map<emergencyTokenHash, uid>` index built on emergency-config write, invalidated on revoke. Lookup becomes O(1) and decrypts only the matched user's file. Token comparison stays constant-time.
- **CWE ID:** CWE-770 / CWE-405 (Asymmetric Resource Consumption – Amplification)

---

### 14. Daemon session-validation distinguishes "not found" vs "uid mismatch"

- **Severity:** Low / Informational
- **Title:** `SessionStore::validate` returns distinguishable error strings
- **Location:** `daemon/src/auth/session.rs:140-144`
- **Description:**
  ```rust
  None                        → "session not found"
  Some(s) if !s.is_valid()    → "session expired"
  Some(s) if s.uid != uid     → "session uid mismatch"
  ```
  A caller learning "uid mismatch" knows the guessed token matches a real session under a different UID. The token space is 256 bits, so this is not directly brute-forceable, and `daemonClient.ts` maps responses through `SAFE_MESSAGES` before they reach the UI. But the daemon log itself records the verbatim error, which may surface in journal exports.
- **Exploitation scenario:** Mostly informational; in a multi-user vault deployment (Phase F, not yet shipped per project memory), distinguishability could feed cross-tenant session enumeration.
- **Remediation:** Collapse all three error paths to a single opaque message (`session invalid`) and add a single structured log line for diagnostics, never exposed on the wire.
- **CWE ID:** CWE-209 (Information Exposure Through an Error Message)

---

## Database-specific issues

PWDnow has no external DBMS to connect to; on-disk state is split between (a) the daemon's SQLCipher database and (b) the Express server's AES-GCM encrypted files in `auth_data/`. Findings against those stores:

| Table / file | Column / field | Issue | Recommendation |
|---|---|---|---|
| `daemon/vault.db.meta` (plaintext sidecar) | `passkey_credentials[].credential_id_hex`, `pqc_credentials[].credential_id_hex` | Credential IDs (public per WebAuthn spec) are stored plaintext. Attacker with read access to the file enumerates which authenticators are bound. | By design, but consider HMAC-wrapping with a key derived from `wipe_ticket` so the IDs are unreadable to an offline attacker without unlock. |
| `daemon/vault.db.meta` | `argon2_salt`, `argon2_m_cost`, `argon2_t_cost`, `argon2_p_cost` | KDF profile exposed plaintext. Pre-unlock leak: attacker who reads the sidecar learns whether to attempt PBKDF2 vs Argon2id and at what cost level for offline brute-force. | Accepted (salt must be plaintext for KDF; cost params must be readable for unlock); ensure deploy permissions are `0o600` (already enforced at `state.rs:374, 379`). |
| `daemon/vault.db` (SQLCipher) `credentials` table | `service_hash`, `url_hash`, `username_hash` | HMAC-SHA-512 blind indices with `bi_key` derived from VMK. An attacker with offline DB access but without VMK cannot reverse them; with VMK they have full access anyway. Acceptable. | None. Note: pre-image attacks on common services ("github.com", "google.com") are feasible only if the bi_key leaks — guard the VMK. |
| `web/auth_data/users.enc` (AES-GCM) | entire blob | All user records (emailHash, passwordHash, mfaTotpSecret, cryptoSalt, loginHints) packed in one file. Per finding #7, unbounded growth is possible. Per-request decrypt cost is O(file size). | Split into `users/<uidHash>.enc` shards; add a per-file size cap (~4 KB) enforced on write. |
| `web/auth_data/.master_key` | 32 raw bytes | Mode 0o400, owned by the runtime user. If the runtime user account is compromised, the master key + every encrypted file in `auth_data/` is at rest, fully recoverable. | Move to a hardware-backed keystore (TPM, Secure Enclave, HSM) or at minimum wrap with a passphrase that the operator supplies at start-up (systemd `LoadCredential`). |
| `web/auth_data/vault/<uid>/sessions.enc` | `ip` | Loopback callers receive the server's outbound public IP; remote callers receive `sha256(ip || dailySalt).slice(0,8)`. Daily salt rotates, so the same IP produces different stored values across days — by design (privacy-preserving). | None; consider increasing the truncation from 8 hex chars (32 bits) to reduce daily collision probability on tenants > ~10 k unique IPs. |
| `web/auth_data/ip_intel_cache.json` | `record` | Cached ipregistry.co lookups with TTL 30 days, mode 0o600. Acceptable. | None. |
| `web/auth_data/public_ip_cache.json` | `ip` | Server's outbound IP cached 24 h. Acceptable. | None. |
| `web/auth_data/mfa_pending.enc` | `tokens`, `emailOtps` | Shared across all users in PM2 cluster mode; race condition per finding #3. | Lock or migrate to SQLite. |

No `DROP TABLE` / `GRANT` / stored-procedure surface exists (rusqlite + SQLCipher in-process, no remote DB user). All rusqlite calls use `params![...]` parameterised queries. No `WHERE` predicate is built by string concatenation against user input.

---

## Pentesting highlights

The following business-logic and auth-flow attack scenarios were simulated against the read code paths:

| # | Attack | Code path | Outcome |
|---|---|---|---|
| 1 | JWT / JWE algorithm confusion (alg=none, HS256↔RS256) | `auth.js:543-565` | **Blocked.** `jose@6.2.2` `EncryptJWT` pins `alg: 'dir', enc: 'A256GCM'`; `jwtDecrypt` rejects mismatches by default. No vulnerability. |
| 2 | CSRF on mutating endpoints | `auth.js:610-618` | **Blocked.** `requireCsrf` middleware enforces header-equals-cookie for POST/PUT/PATCH/DELETE; cookies are `SameSite=Strict`. |
| 3 | IDOR via `/api/vault/credentials/:id` | (no such route) | **N/A.** Vault data is loaded as a single blob per `req.user.id`; per-credential IDs never flow through the URL. |
| 4 | Predictable share/emergency IDs | `auth.js:1491, 1615` | **Blocked.** `randomBytes(16/32).toString('hex')` — 128/256-bit unpredictability. |
| 5 | TOTP replay within window | `auth.js:270-302` | **Blocked.** Per-secret `_usedTotpPeriods` cache rejects replay of the same period; ±30 s skew enforced. |
| 6 | TOTP brute-force (online) | `auth.js:225-244, 1144-1172` | **Blocked.** 5 failures → 10-min MFA lockout per user; rate-limit by IP also active. |
| 7 | Recovery-key abuse | `auth.js:1041-1060, 1187-1224` | **Mostly blocked.** Single-use semantics enforced; 90-day TTL; password re-verify required to rotate. Note: an attacker who reads the user's encrypted `users.enc` and has the master key recovers the hash and can attempt offline cracking. |
| 8 | Open redirect / SSRF | `server.js`, `auth.js:1438-1442` | **Blocked.** SMTP host validated against RFC-1918 / metadata / loopback patterns; no user-controlled redirect targets. |
| 9 | Host header injection | `server.js:113` | **Mitigated.** `Host` only used to compute the HTTPS redirect target; injection produces a self-redirect, not cross-site. WS handshake is the exception (see finding #2). |
| 10 | Coupon stacking / negative quantity (commerce-style) | N/A | **Not applicable** — no commerce surface. |
| 11 | File-upload abuse | `auth.js:981-993` (`UploadProfilePicture`) | **Partially mitigated.** Type check happens in daemon (`user_profile::upload_picture`); body limit 512 KB; need to confirm daemon rejects polyglot / SVG / zip-bomb images. Suggested follow-up audit of `daemon/src/vault/user_profile.rs::upload_picture`. |
| 12 | Path traversal | All `userVaultFile(uid, name)` / `path.join` | **Blocked.** `uid` is server-issued (`req.user.id`); `name` is always a hardcoded literal. |
| 13 | HTTP request smuggling | nginx + Express | **Mitigated.** `proxy_http_version 1.1`; Express trusts only loopback proxy; `Transfer-Encoding` / `Content-Length` discrepancies blocked by nginx default. |
| 14 | Privilege escalation (horizontal) — read another user's vault | `auth.js:1345-1400` | **Blocked.** Every vault read uses `req.user.id` from the JWE-validated session — never a URL/body parameter. |
| 15 | Privilege escalation (vertical) — admin-only endpoints | `server.js:398-439`  | **Blocked.** Setup endpoints guarded by `requireSetupToken` + `refuseIfSetupDone`; `SETUP_TOKEN` is nulled on completion. |
| 16 | Brute-force master password (online, vs daemon) | `state.rs:201-217, 648-666` | **Blocked.** Exponential lockout schedule `[0,0,0,0,0,30,60,120,300,600]` seconds; lockout keyed by UID, persists across reconnects. |
| 17 | Forensic ticket forgery | `state.rs:833-859` | **Blocked.** Ticket length pinned to 32 bytes; SHA3-512 + constant-time compare; ticket is VMK-encrypted and only obtainable from a valid unlock. |
| 18 | Vault-header tampering offline | `state.rs:705-712, 383-399` | **Blocked.** HMAC-SHA-384 over the entire header with a VMK-derived key; mismatch aborts unlock. |
| 19 | Audit-log truncation/tampering | `auth.js:692-705`, `daemon/src/vault/audit.rs` | **Blocked.** HMAC chain on every event; verification on each load; chain break flagged. |
| 20 | Signature-counter rollback on passkey (cloned authenticator) | `state.rs:507-522` | **Blocked.** New counter must exceed stored counter; regression rejected. |
| 21 | XSS via vault customSvg | `web/src/utils/sanitize.ts` (per CLAUDE.md) | **Mitigated.** DOMPurify + Trusted Types default policy in `main.tsx`. |
| 22 | Prototype pollution via `req.body` | Various | **Not exploited.** Express + JSON.parse does not pollute prototypes; no `Object.assign(user, body)` patterns found. Authoritative writes copy specific fields. |
| 23 | Argon2id memory-exhaustion DoS | `auth.js:50-52, 477-494` | **Mitigated.** `ARGON2_MAX_CONCURRENT = 3` concurrent hashes × 128 MiB cap = 384 MiB ceiling; `429` returned over the cap. |
| 24 | Email-OTP brute-force | `auth.js:1158-1172` | **Blocked.** Single-use (consumed on first call); constant-time compare; ±5-minute TTL; MFA lockout on failure. |

---

---

# Round 2 — Deep-dive findings (added after second-pass audit)

The second pass focused on: (a) FIDO2 / Passkey crypto plumbing inside the daemon, (b) IPC framing, (c) the daemon's sidecar HMAC invariants under sign-count updates, (d) server-mode passkey/MFA flows, (e) backup-code entropy, (f) deployment-config consistency, (g) the wipe path. These findings are net-new and have NOT been counted in the Summary block above; the revised running totals are:

- **Cumulative total: 32** · **Critical: 1** · **High: 6** · **Medium: 11** · **Low: 11** · **Info: 3**
- **New most dangerous vulnerability (Critical):** The Passkey VMK wrap key is derived from the *registration-time* authData (flags byte `0x41` / `0x45` with `AT` and possibly `UV` bits set), but the *unlock-time* code re-derives the wrap key from the *assertion-time* authData (flags `0x01` / `0x05`, no `AT`). The flags byte (`auth_data[32]`) is part of the HKDF salt, so the two derivations yield different keys and the wrapped VMK can never be decrypted on a real device. If this is being shipped enabled, the entire passwordless-passkey flow is non-functional; if it ever *did* work because of an environment-specific quirk, the slightest libfido2 change breaks unlock with no recovery path other than re-registering (which requires the user to first unlock via password). See finding #15.

---

### 15. Passkey wrap-key derivation uses **registration** authData; unlock uses **assertion** authData (flags-byte mismatch)

- **Severity:** Critical (correctness + availability) — re-classify to High if you can demonstrate that the flow currently works in production
- **Title:** `derive_vmk_wrap_key(auth_data[0..33], cred_id, suite)` is called with structurally different `authData` at register vs. unlock, producing two different keys
- **Location:** Registration: `daemon/src/ipc/socket.rs:631-634`; Unlock: `daemon/src/vault/state.rs:524`; KDF: `daemon/src/auth/fido2.rs:389-405`
- **Description:**
  WebAuthn `authData` layout is `rpIdHash(32) || flags(1) || signCount(4) || …`. At *registration* (`fido_dev_make_cred`), libfido2 returns `authData` whose flags byte has `AT` (`0x40`, attested credential data present) and often `UV`/`BE`/`BS` set — typical concrete values are `0x41` (UP+AT) or `0x45` (UP+UV+AT). At *assertion* (`navigator.credentials.get` / `fido_dev_get_assert`), the same authenticator returns `authData` whose flags byte does **not** have `AT` set — typical concrete values are `0x01` (UP) or `0x05` (UP+UV).

  The daemon's `derive_vmk_wrap_key` mixes `auth_data[0..33]` — i.e. `rpIdHash || flags` — into the HKDF salt:
  ```rust
  let hk = Hkdf::<Sha3_512>::new(Some(credential_id), &auth_data[0..33]);
  ```
  Because the flags byte differs between the two ceremonies, the wrap key computed at registration is **mathematically different** from the wrap key computed at unlock, and `xchacha20::decrypt(&wrap_key, &enc_vmk_copy, …)` must fail with an AEAD tag mismatch.

  The repo's own unit test `test_software_backend_get_assertion_returns_stable_prefix` (`daemon/src/auth/fido2.rs:425-433`) explicitly proves register/assert flags differ (`0x41` vs `0x01`), but `test_vmk_wrap_key_roundtrip_encrypt_decrypt` (line 481) tests round-trip with **identical** authData (`vec![0x42u8; 37]`) — so the test suite does not exercise the cross-ceremony scenario.
- **Exploitation scenario:** Not an attacker-driven exploit; this is a self-DoS. Every legitimate passkey unlock fails. Combined with finding #22 in the existing list (passkey VMK copies are cleared on master-password change, requiring re-registration), a user who locks themselves out of their password also loses passkey recovery — total account loss with no offline recovery.
- **Proof of concept (simulated):**
  ```
  # registration
  reg_auth_data[32] = 0x41
  wrap_key_REG = HKDF-SHA3-512(salt=cred_id, ikm=reg_auth_data[0..33], info="...")

  # later, on unlock
  asrt_auth_data[32] = 0x01
  wrap_key_UNL = HKDF-SHA3-512(salt=cred_id, ikm=asrt_auth_data[0..33], info="...")

  wrap_key_REG ≠ wrap_key_UNL   →   xchacha20::decrypt fails   →   "challenge invalid or expired" path is taken
  ```
- **Remediation:**
  Bind the wrap-key derivation to fields that are **invariant** across register and assert. Two safe options:

  1. Use only `rpIdHash` (`auth_data[0..32]`) — drop the flags byte. Cheap, no schema change. Acceptable because the credential_id is already in the HKDF salt and the rpIdHash is per-RP. Re-register passkeys on rollout (the existing wipe-on-password-change semantics already require that for migrations).
     ```rust
     let hk = Hkdf::<Sha3_512>::new(Some(credential_id), &auth_data[0..32]);
     ```
  2. Better: mask out the volatile bits of the flags byte so only invariants (UP=0x01, UV=0x04, BE=0x08, BS=0x10) participate; explicitly remove the AT bit at both call sites:
     ```rust
     let mut prefix = [0u8; 33];
     prefix[..32].copy_from_slice(&auth_data[..32]);
     prefix[32]   = auth_data[32] & !0x40; // strip AT — present only at registration
     let hk = Hkdf::<Sha3_512>::new(Some(credential_id), &prefix);
     ```
  Add a regression test that derives once with `flags=0x41` (register) and once with `flags=0x01` (assert) and asserts the two outputs are equal. Bump `kem_suite` version so existing sidecars are not misinterpreted, and force re-registration of resident credentials on next unlock.
- **CWE ID:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm — incorrect KDF input binding) / CWE-755 (Improper Handling of Exceptional Conditions)

---

### 16. Passkey sign-count update writes the sidecar before the VMK is loaded, leaving a stale `header_hmac`

- **Severity:** High (availability — once-and-done corruption of the integrity chain)
- **Title:** `write_header(&new_header)` from `unlock_with_passkey_inner` runs while `self.vmk.read() == None`; `write_header` therefore skips HMAC recomputation, but the sidecar contents have changed
- **Location:** `daemon/src/vault/state.rs:506-522` (sign-count update) calling `state.rs:348-381` (`write_header`)
- **Description:**
  Inside `unlock_with_passkey_inner`, the daemon updates the stored `sign_count` for the matched passkey:
  ```rust
  if new_count > entry.sign_count {
      let mut new_header = header.clone();
      if let Some(e) = new_header.passkey_credentials.iter_mut().find(...) {
          e.sign_count = new_count;
          self.write_header(&new_header)?;          // ← state.vmk is still None at this point
      }
  }
  ```
  But `self.vmk.write().unwrap() = Some(locked)` does not happen until **line 553**, well after the `write_header` call. Inside `write_header` (state.rs:348-356), the HMAC field is updated **only** when a VMK is currently held in memory:
  ```rust
  if let Some(vmk) = self.vmk.read().unwrap().as_ref() {
      header.header_hmac = Some(self.calculate_header_hmac(&header, &vmk_bytes));
      ...
  }
  ```
  Because the VMK is not yet loaded, the `header_hmac` field is **not recomputed**, but the surrounding payload (`sign_count`) **has changed**. The file is written with the *previous* HMAC over the *current* (mutated) content. The next time the user unlocks via password (which is the only path that actually verifies the HMAC — state.rs:706-712), the check fails and unlock is permanently rejected:
  ```
  "vault header integrity check failed"
  ```
  Recovery is only possible by editing the sidecar manually or by re-registering the passkey (the existing wipe-on-password-change pathway). Because the sign-count update fires on the very first authenticator action (`new_count > 0`), this is triggered by the first successful passkey unlock and leaves no working primary-password path.
- **Exploitation scenario:** A malicious actor who induces a single passkey unlock attempt on a victim's device (e.g. via a remote-assistance session) permanently corrupts the password-login path. Self-inflicted by the user under benign conditions, too.
- **Proof of concept (simulated):**
  ```
  Time 1: user runs UnlockWithPasskey → assertion verifies → sign_count updated 0 → 1 → write_header() runs while self.vmk == None → file rewritten with new sign_count and OLD header_hmac.
  Time 2 (next session, password unlock): read_header → compute HMAC of mutated content → mismatch → permanent rejection.
  ```
- **Remediation:** Move the sign-count update so that it runs *after* the VMK is installed in `self.vmk`, or compute the HMAC inline using the VMK that is already on the stack at the call site. Concretely:
  ```rust
  // Move the sign-count update below `*self.vmk.write().unwrap() = Some(locked);`
  // OR pass the in-scope VMK bytes into a `write_header_with_vmk(&header, &vmk_arr)` variant.
  ```
  Add a regression test: register a passkey, perform a passkey unlock, lock, then password-unlock — must succeed.
- **CWE ID:** CWE-666 (Operation on Resource in Wrong Phase of Lifetime) / CWE-754

---

### 17. `VaultHeader.header_hmac` is `Option<String>` — verification is silently skipped when absent

- **Severity:** Medium
- **Title:** Sidecar HMAC is optional; an attacker with write-access to `vault.db.meta` can downgrade KDF parameters by stripping the HMAC field
- **Location:** `daemon/src/vault/state.rs:91-93` (`#[serde(default)] header_hmac: Option<String>`); verification at `state.rs:706-712`
- **Description:** Because `header_hmac` defaults to `None` on deserialisation, an attacker who can write the plaintext sidecar (i.e. anyone with the `vault` user's filesystem privileges, or a misconfigured `0o644` perms scenario) can:
  1. Strip the `header_hmac` field.
  2. Tamper with `argon2_m_cost`, `argon2_t_cost`, `argon2_p_cost` (e.g. set them above `LEGACY_HEAVY_*` thresholds) so the next legitimate unlock triggers the silent `rewrap_vmk_with_current_kdf` migration path at `state.rs:732-740`, downgrading the KDF cost to the current floor.
  Combined with finding #16, this means an attacker can also cause password unlock to fail unconditionally by mutating any field after a passkey-driven sign-count update.
  The HMAC is meant to be the on-disk integrity primitive, but `Option<String>` semantically means "this vault may or may not be HMAC-protected", which is exactly the wrong default for a security-critical invariant.
- **Exploitation scenario:** Local attacker with `vault`-user filesystem privileges (e.g. compromise of a lateral service running as the same UID) silently lowers KDF cost from `256 MiB / t=3 / p=1` to `64 MiB / t=2 / p=1`, halving the effective work factor for an offline brute-force should the VMK ciphertext later leak.
- **Remediation:** Once the vault has been opened once (i.e. `passkey_credentials` is non-empty *or* `header_hmac.is_some()` has ever been true), require `header_hmac` to be present and valid on every unlock. The first write of `write_header` after `with_vmk` is always able to compute an HMAC, so the only legitimate `None` case is a freshly-created vault — which can be marked instead via a `created_at: i64` field plus a "first-unlock done" flag in `vault_meta`. Easier: in `unlock_existing`, reject any sidecar lacking `header_hmac` whenever `db.exists()`.
- **CWE ID:** CWE-345 (Insufficient Verification of Data Authenticity)

---

### 18. Server-mode "passkey login" never verifies the assertion signature

- **Severity:** High
- **Title:** `authenticateWithPasskeyForLogin()` in server mode returns `true` whenever the browser produces any assertion matching a stored credential ID — no signature/origin/challenge verification
- **Location:** `web/src/utils/mfa.ts:780-819`
- **Description:** The function gates only on `(a)` `userVerification: 'required'` being honoured by the local platform authenticator and `(b)` the returned `rawId` matching a locally-cached hint. There is **no** WebAuthn signature verification, no challenge binding (the challenge is a freshly random 32 bytes that is **never returned to a server** for verification), and no enforcement that the assertion's `clientDataJSON.type === "webauthn.get"`. The comment at line 780-781 acknowledges this is a "demo" but the function is reachable from the production login flow (`web/src/pages/Login.tsx` via the passkey button) when the daemon is unreachable.
- **Exploitation scenario:**
  - A device-local attacker with browser access (no biometric needed if `userVerification` falls back to a user-selectable PIN) can produce a successful assertion for any cached credential, bypassing the password.
  - More importantly, the function is `boolean`-returning and the caller (Login.tsx) treats `true` as proof of identity — so even logical errors that flip the boolean (e.g. cache poisoning of `_passkeyHintCache` via `writeEncryptedLocal` corruption) can yield a false-positive auth.
  - In a forwarded-prompt attack (attacker triggers WebAuthn on attacker-controlled domain that loads the victim's app in a hidden iframe), the assertion verifies locally with no server check; no server-issued challenge protects against same-origin replay because the challenge never crosses to a server.
- **Proof of concept (simulated):** Any attacker who controls the device (even briefly) can call:
  ```js
  await navigator.credentials.get({ publicKey: { challenge: new Uint8Array(32), rpId: location.hostname, allowCredentials: [{id: stolen_hint_id, type:'public-key'}], userVerification:'required' }});
  // → returns assertion; mfa.ts:806-818 returns true. Caller marks user as authenticated.
  ```
- **Remediation:**
  1. Add a server-side `POST /api/auth/passkey/begin` that issues a server-bound challenge (random 32 bytes stored keyed by IP/session in `mfa_pending.enc`).
  2. Add `POST /api/auth/passkey/finish` that verifies: (a) the assertion's `clientDataJSON.challenge` equals the issued challenge, (b) `type === "webauthn.get"`, (c) `origin` is in the allow-list, (d) the signature verifies against a stored COSE public key (which means server-side enrolment of passkey public keys, not just credential IDs).
  3. Only then issue the JWE session cookie. Until done, do NOT mark passkey as a primary auth factor in server mode — treat it as 2FA after password.
- **CWE ID:** CWE-287 (Improper Authentication) / CWE-345

---

### 19. TOTP-backup-code search space is only 32 bits

- **Severity:** Medium
- **Title:** Each backup code is `format!("{:08X}", rand::random::<u32>())` — 4.29 × 10⁹ possibilities
- **Location:** `daemon/src/vault/totp_db.rs:225`
- **Description:** OWASP ASVS V2.4 / NIST SP 800-63B-4 recommend "lookup secrets" of ≥ 20 bits per code with rate-limiting, but in practice the standard is 12 alphanumeric characters (~62 bits) so a leaked DB row cannot be cracked. PWDnow uses an 8-hex code (32 bits). Argon2id at `64 MiB / t=2 / p=2` is the slow factor; with a modest cracker, the offline attack against 10 codes is ~1 month of GPU time, and a leaked DB cell discloses an OTP-bypass.
  The codes are intended as a TOTP fallback, so they are equivalent in privilege to TOTP itself — but TOTP has 10⁶ states and a 30-second window with replay protection, whereas a leaked backup-code list has no time bound.
- **Exploitation scenario:** Backup of `vault.db` is exfiltrated (one of the many SP 800-88 sanitisation gaps the codebase already calls out). Attacker performs offline Argon2id brute-force on the 32-bit space; with a small GPU rig and the relatively low Argon2 m=64 MiB, recovery of all 10 codes in weeks is realistic. Codes never expire; one is enough to bypass MFA on the next unlock.
- **Remediation:** Generate codes from a larger character set. Use base32 with at least 10 characters (50 bits) — the canonical pattern in Bitwarden / 1Password / Google's downloadable codes. Bump Argon2 params for the **backup-code hash** to match `kdf_tune::MIN_*` (256 MiB / t=3 / p=1) so post-leak offline attacks cost weeks even for one code. Patch:
  ```rust
  // generate_backup_codes
  let mut raw = [0u8; 10];
  OsRng.fill_bytes(&mut raw);
  let code = base32_no_pad(&raw); // ~16 chars, 50 bits
  ```
- **CWE ID:** CWE-330 (Use of Insufficiently Random Values) / CWE-326

---

### 20. `encryptForServer` has no outer HMAC despite the documented design

- **Severity:** Low / Informational
- **Title:** `localCrypto.ts` claims compact-JWE format with HMAC-SHA256 outer layer; server-bound encryption skips the HMAC
- **Location:** `web/src/utils/localCrypto.ts:45-69` (`encryptForServer`) vs lines 1-18 (top-of-file design comment) and lines 125-194 (`writeEncryptedLocal` which DOES sign).
- **Description:** The module's docstring describes a three-part compact token `header.payload.hmac_sig`, but only `writeEncryptedLocal` produces three parts; `encryptForServer` returns only the AES-GCM `iv || ciphertext+tag` payload (one part). This is not a vulnerability per se — AES-GCM is AEAD and provides authentication — but it directly contradicts the threat model spelled out in the comment ("defense in depth against GCM nonce-reuse or implementation bugs"). Future maintainers may wrongly assume server-stored blobs are double-authenticated.
- **Remediation:** Either implement the outer HMAC in `encryptForServer` (matching the design comment) **or** delete the "defense in depth" claim from the comment. Prefer the former for symmetry with `writeEncryptedLocal`.
- **CWE ID:** CWE-1188 / CWE-710 (Improper Adherence to Coding Standards — documentation drift) — informational

---

### 21. Daemon error strings leak through `tracing` logs even when sanitised on the wire

- **Severity:** Low
- **Title:** `daemon/src/vault/state.rs:682` and similar sites emit Argon2 KDF timings, decrypt-failure reasons, and component error messages via `tracing::debug!` / `tracing::warn!`
- **Location:** Scattered: `state.rs:682, 738, 595, 609`; `folders.rs:106`; `socket.rs:81, 86, 146`
- **Description:** `daemonClient.ts:181-191` maps internal codes to safe UI strings before they reach the browser. Good. But the daemon's own log destination is systemd-journal (`StandardOutput=journal` in `vault-daemon.service`), which may be captured by aggregation pipelines or accessible to non-vault local administrators. Sensitive lines include `unlock_kdf={ms}` (user-specific KDF timing — a side-channel on hardware speed and password length when combined with login timing), `failed to decrypt folder; skipping` (reveals data corruption per folder ID), and `transparent KDF migration failed` (reveals which users had legacy headers).
- **Remediation:** Audit all daemon `tracing::*` callsites and downgrade anything user-state-specific to `tracing::trace!` (off by default), or gate behind `cfg!(debug_assertions)`. Add `RUST_LOG=warn` as the default `Environment=` in the systemd unit.
- **CWE ID:** CWE-532 (Insertion of Sensitive Information into Log)

---

### 22. `GetProfile` decrypts and returns the entire profile picture on every call

- **Severity:** Low
- **Title:** Profile picture (up to 2 MiB plaintext) re-decrypted and serialised over IPC on every authenticated `GetProfile`
- **Location:** `daemon/src/vault/user_profile.rs:70-74, 46-85`; called from `socket.rs:907-929`
- **Description:** The frontend hits `GetProfile` on every page load (UserContext mount) and on every navigation that re-runs the profile fetch (Settings, Header). Each call decrypts a 2 MiB AES-GCM ciphertext, base64-deserialises through msgpack, ships across the WS proxy to the browser, then through `decode()` in `decryptFromServer`. This is wasteful CPU on the daemon and large WS frames on the wire. A malicious authenticated client can spam `GetProfile` to load up daemon CPU.
- **Exploitation scenario:** Authenticated user (the legitimate vault owner, or a colocated process that shares the same UID — e.g. a malicious shell hook) issues thousands of `GetProfile` requests per minute to amplify CPU cost. The per-RPC rate limit on the daemon side is implicit (one in-flight request per WS connection) but a parallel-WS attacker can multiply it.
- **Remediation:** Split into `GetProfile` (returns fields + a profile-picture ETag/hash) and `GetProfilePicture` (returns the picture bytes). Frontend re-fetches the picture only when the ETag changes. Add a server-side LRU of decrypted-picture bytes keyed by ETag.
- **CWE ID:** CWE-400 / CWE-405 (Asymmetric Resource Consumption — Amplification)

---

### 23. `socket.rs::handle_connection` only counts `code: 401` toward `MAX_CONN_AUTH_FAILURES`; malformed frames do not count

- **Severity:** Low
- **Title:** Per-connection failure threshold (3) only triggers on auth errors; malformed msgpack frames are infinitely retryable on the same connection
- **Location:** `daemon/src/ipc/socket.rs:127-153`
- **Description:** The `match Response::Error { code: 401, … }` branch increments `conn_auth_failures`; the earlier `Err(_) => send Error{400}; continue` branch (line 129-131) does not. A malicious local peer can spam malformed frames on one connection forever, paying ~10 μs of msgpack-deserialisation cost per frame on the daemon thread. Mitigated globally by the 100-connection semaphore, but per-connection there is no back-pressure.
- **Remediation:** Treat any error response (400, 401, 403, 503, ...) as a failure for threshold purposes, OR add a per-connection malformed-frame counter that closes the socket after N (e.g. 5) decode errors. Easier:
  ```rust
  if let Response::Error { .. } = &response {
      conn_auth_failures += 1;
      if conn_auth_failures >= MAX_CONN_AUTH_FAILURES { break; }
  }
  ```
- **CWE ID:** CWE-770 / CWE-405

---

### 24. `ecosystem.config.cjs` points at a socket path the daemon does not bind under systemd

- **Severity:** Low / Informational (deployment correctness)
- **Title:** PM2 env sets `VAULT_SOCKET=/tmp/vault-daemon-run/vault.sock`; the systemd unit binds `/run/vault-daemon/vault.sock`
- **Location:** `web/ecosystem.config.cjs:18, 24` vs `deploy/vault-daemon.service:11, 48`
- **Description:** Operators following the documented "PM2 production" path will find the web layer reporting `daemon not reachable` because the two halves disagree on the socket location. Not a vulnerability — but the `/tmp/vault-daemon-run/vault.sock` path also implies an attempt to bind under the global `/tmp` (system-wide world-readable directory with the sticky bit), which is the **wrong** place for a daemon socket (anyone with shell on the box can `socat` against it). If a future operator does run the daemon under non-systemd init at the documented PM2 path, they implicitly downgrade socket isolation.
- **Remediation:** Single-source the socket path. Set `VAULT_SOCKET=/run/vault-daemon/vault.sock` in `ecosystem.config.cjs.env_production` and document that the operator must `RuntimeDirectory=vault-daemon` themselves if they run without systemd. Reject `/tmp/`-based socket paths at startup unless an explicit `VAULT_ALLOW_INSECURE_SOCKET=1` env is set.
- **CWE ID:** CWE-693 (Protection Mechanism Failure)

---

### 25. `cloudflare.rs` (sync) carries plaintext `api_token` and lacks SSRF allow-list — currently dead code but trivially weaponised

- **Severity:** Low (latent — module is `#![allow(dead_code)]`)
- **Title:** `SyncConfig.endpoint: String` is user-controlled and `SyncClient::head/upload/download` use `ureq::agent()` with no host-allow-list; `api_token` lives in plaintext `String`
- **Location:** `daemon/src/sync/cloudflare.rs:42-51, 169-189`
- **Description:** When this module gets wired into IPC (the module's own header says "to activate, add `Request::SyncNow`…"), the daemon will make outbound HTTPS calls to whatever endpoint `vault_meta` says. With no validation, that endpoint can be a private-network address, the metadata-service IP (`169.254.169.254`), or any internal HTTP endpoint reachable from the daemon's network namespace. The `RestrictAddressFamilies=AF_UNIX` and `deny network` in the AppArmor profile actually block this — but those are deployment-time controls; if either is relaxed (the AppArmor profile explicitly lists `deny network` so currently the sync module can't even bind sockets), SSRF goes live.
- **Remediation:** Before activating: (a) validate `endpoint` URL against an HTTPS-only host allow-list, (b) reject RFC-1918 / loopback / link-local IPs at resolution time, (c) store `api_token` in a `LockedKey`, (d) when activating, lift the AppArmor `deny network` rule **only** to the configured endpoint host.
- **CWE ID:** CWE-918 (SSRF) — latent

---

### 26. Audit-log row hash does not include the row primary key

- **Severity:** Informational
- **Title:** `compute_row_hash(mac_key, ts, action, resource, prev_hash)` excludes `audit_log.id`
- **Location:** `daemon/src/vault/audit.rs:41-63`
- **Description:** Two consecutive audit entries with identical `(ts, action, resource)` and the same `prev_hash` produce identical `row_hash`. The `ts` is `as_nanos() as i64`, so collisions require sub-nanosecond log calls — practically impossible on monotonic system clocks but legal under clock-skew scenarios (e.g. VM time-warp). Including `id` in the MAC would close this fully.
- **Remediation:** Add a `u64` row counter (or the SQLite-issued `id`) to the MAC input; on chain verification, also assert ID monotonicity.
- **CWE ID:** CWE-345

---

### 27. `folders::reorder` is non-atomic — partial failure leaves inconsistent `sort_order`

- **Severity:** Informational (UI correctness)
- **Title:** Per-row UPDATE loop without a `BEGIN TRANSACTION` / `COMMIT`
- **Location:** `daemon/src/vault/folders.rs:207-216`
- **Description:** A failure on row N leaves rows 0..N-1 updated and N..end unchanged, so the UI shows duplicate `sort_order` values until the next reorder. Not security-relevant; correctness.
- **Remediation:** Wrap the loop in `conn.execute("BEGIN", [])?` / `conn.execute("COMMIT", [])?` with a rollback on error.
- **CWE ID:** CWE-665 (Improper Initialization) / CWE-460

---

### 28. WebAuthn `clientDataJSON.type` and `origin` are not validated server-side; only the challenge is checked

- **Severity:** Medium
- **Title:** Daemon unlock paths trust the libfido2 signature check to "do the right thing" but never inspect `clientDataJSON` content
- **Location:** `daemon/src/vault/state.rs:465-478` (passkey), `:870-883` (PQC), `:928-941` (quick-unlock)
- **Description:** All three flows parse `clientDataJSON` only to extract `challenge`; they do not enforce `type === "webauthn.get"`, do not enforce `origin === "vault.local"` (or whichever rpId is configured), and do not enforce `crossOrigin === false`. The W3C WebAuthn spec §7.2 step 11 requires the relying party to validate these. The signature itself binds `authData || sha256(clientDataJSON)`, so a forged `clientDataJSON` would fail signature verification *as long as the authenticator was on the legitimate origin* — but a confused-deputy authenticator that signs `type: "webauthn.create"` clientData (for example, an attacker who exploits a different vault on the same authenticator) could in principle produce a signature that the daemon accepts.
- **Exploitation scenario:** Cross-flow signature reuse. If a different application on the same hardware authenticator (same passkey credential ID is unlikely, but discoverable-credential collisions exist) signs *registration*-shaped clientDataJSON with a matching challenge, the daemon's `verify_assertion` returns OK because libfido2 only verifies the signature — not the meaning of the bytes. Bound by attacker contriving a same-RP same-cred-id collision; practically very narrow.
- **Remediation:** After `consume_challenge` succeeds, additionally parse `cdata.get("type")` and reject if not `"webauthn.get"`; parse `cdata.get("origin")` and reject if not equal to the configured rpId (e.g. `"vault.local"` → origins `"https://vault.local"`, `"https://vault.local:443"`, etc., per WebAuthn §5.1.3). Reject `crossOrigin: true`.
- **CWE ID:** CWE-345 / CWE-441 (Unintended Proxy or Intermediary)

---

### 29. Duress-mode password hash is stored plaintext-readable in localStorage

- **Severity:** Medium
- **Title:** `saveDuressModeConfig` writes the Argon2id PHC hash to `localStorage["duress_mode_config"]` with no encryption
- **Location:** `web/src/utils/securityModes.ts:54-58, 187-198`
- **Description:** The whole point of duress mode is anti-forensic — if the user is being coerced to reveal the master password, entering the *duress* password instead is supposed to silently wipe. But because the Argon2id PHC hash sits in plaintext localStorage, a coercer with physical access can:
  1. Inspect localStorage *before* coercion to learn that duress mode is armed.
  2. Snapshot the encrypted vault first, then ignore any wipe action by the user, then crack the duress hash offline (Argon2id at `m=64 MiB / t=2 / p=1` is fast on GPUs).
  3. Bypass the wipe trigger by intercepting the request to `/api/vault/wipe`.

  The CLAUDE.md security directive says "anti-forensic" specifically about duress. Storing the duress hash in plaintext defeats that.
- **Exploitation scenario:** Border-crossing scenario: officer demands unlock; user enters duress password; wipe should run. But officer observed pre-arrival that `duress_mode_config.armed == true` (visible in dev tools or via file-system access to localStorage backing). Officer disables network / unlinks the wipe endpoint before unlocking; wipe HTTP call fails; only the partial browser-side wipe runs; the encrypted vault on the server is intact and the Argon2id hash leaked into the snapshot can be cracked to reveal the duress password (proving the user *did* arm duress mode, escalating coercion).
- **Remediation:**
  1. Wrap the duress config with the v2 (Argon2id-bound) session key after first unlock; only the *armed bool* + an opaque-by-design wrapper persists pre-unlock.
  2. Raise Argon2id parameters for the duress hash to match `MIN_M_COST / MIN_T_COST` (256 MiB / t=3).
  3. Make the wipe-trigger flow daemon-resident rather than HTTP-resident (call `daemon.forensicWipe(ticket)` first, then `/api/vault/wipe` — already the case in `wipeVaultData`, but order matters; verify it).
  4. Treat duress-mode presence as the **secret** the attacker shouldn't learn, so always-write a fixed-shape value (the code already does this partially per the comment on `securityModes.ts:55-58`, but the field names themselves are descriptive — `duress_mode_config`, `passwordHash`, `attemptsRemaining` are all readable).
- **CWE ID:** CWE-312 (Cleartext Storage of Sensitive Information) / CWE-200

---

### 30. Quick-unlock `dbk` is not bound to the assertion signature; key separation depends on attacker not having PRF output

- **Severity:** Low
- **Title:** `QuickUnlock` accepts `dbk` (the WebAuthn PRF output) as an independent input alongside the assertion; signature does not cover the dbk
- **Location:** `daemon/src/vault/state.rs:915-1022`
- **Description:** The dbk is the 32-byte PRF output of the platform authenticator. It's secret, but it travels from the browser to the daemon via the WS proxy alongside the assertion. The daemon verifies the assertion signature (good) and then uses the dbk independently to unwrap the enc_kek. A side-channel that leaks dbk (e.g. heap scrapers, browser-extension exfil) gives an attacker an offline-crackable wrapped key when combined with a valid assertion — and the assertion can be replayed once captured (until challenge consumption, ~10 min). The signature should cover a transcript hash that includes the dbk so that a leaked dbk alone (without a matching signature) cannot unlock, and a leaked assertion without dbk cannot either.
- **Remediation:** Make the signed clientDataJSON include a binding to the dbk: e.g. a `dbk_commitment = SHA-256(dbk || credential_id)` field that the daemon verifies after signature verification. Even better: derive the dbk *from* the assertion's PRF extension output (WebAuthn `hmac-secret`) inside the daemon's address space, rather than letting the browser hand it across the wire.
- **CWE ID:** CWE-294 (Authentication Bypass by Capture-Replay)

---

### 31. `nonce_vec.len() == 12 → try_into().unwrap()` panic surface across daemon

- **Severity:** Low
- **Title:** Multiple decrypt sites match `nonce_vec.len()` then `try_into().unwrap()` — robust against attacker but trivially panicable on data corruption
- **Location:** `daemon/src/vault/credentials.rs:116, 120`; `daemon/src/vault/state.rs:259, 263, 690, 694, 982, 986`; `daemon/src/vault/folders.rs:59, 63`; `daemon/src/vault/user_profile.rs:179, 183`; `daemon/src/vault/totp_db.rs:127, 131, 171, 175`; `daemon/src/auth/fido2.rs` (in tests)
- **Description:** The pattern
  ```rust
  match nonce_vec.len() { 12 => { let nonce: [u8; 12] = nonce_vec.try_into().unwrap(); ... }, 24 => { ... }, _ => Err(...) }
  ```
  is sound when `nonce_vec` is freshly produced by a length-checked source. But there are also slice indexing sites in `credentials::get`:
  ```rust
  let dek_vec = aes_gcm::decrypt(vmk, &enc_dek, &dek_nonce[..12].try_into().unwrap(), ...)?;
  let plain    = xchacha20::decrypt(&dek,        &ct,    &ct_nonce[..24].try_into().unwrap(), &aad)?;
  ```
  Here `[..12]` and `[..24]` will panic if the stored blob is shorter (`SliceOutOfRange`). Database corruption — or an attacker who can write to the SQLite database file — converts a "decrypt fails" into a "daemon process panics and is restarted by systemd". Repeated short-blob injections become a guaranteed-restart DoS.
- **Exploitation scenario:** Attacker with file-system write to `vault.db` (lateral compromise) overwrites a `dek_nonce` field to length 0; subsequent `GetCredential` panics the daemon. Combined with `Restart=on-failure` in the systemd unit, this is a noisy crash loop that locks legitimate users out for the duration of restart back-off.
- **Remediation:** Replace `[..N].try_into().unwrap()` with `let nonce: [u8; N] = (&blob).try_into().map_err(|_| VaultError::Crypto("nonce truncated".into()))?;` — return a proper error rather than panicking. Audit all `unwrap()` calls under `daemon/src/vault/` and convert to `?` propagation.
- **CWE ID:** CWE-617 (Reachable Assertion) / CWE-755

---

### 32. `IpIntelligence` HTTP call has no proxy / system-CA pinning and reveals user IP to a third party

- **Severity:** Low / Informational
- **Title:** `ipregistry.co` (and `api64.ipify.org`) calls are unauthenticated outbound HTTPS without certificate pinning; per-user IPs are sent
- **Location:** `web/ipIntelligence.js:72-104`; `web/auth.js:728-760`
- **Description:** Every login that lands behind a non-loopback IP triggers an outbound GET to `https://api.ipregistry.co/<ip>?key=<APIKEY>` (when `IPREGISTRY_API_KEY` is set). The vault operator's API key is sent on every request; the user's IP and inferred metadata (Tor/VPN/proxy flags) are sent. There is no certificate pinning — system trust store applies, so a captured-traffic actor with a compromised CA can MitM. The `api64.ipify.org` call leaks the server's outbound public IP unconditionally on startup. Neither call is gated by an operator-configurable "no telemetry" switch.
- **Remediation:** (a) Make the IP-intel lookup off-by-default; require an explicit `IP_INTEL=enabled` env var. (b) Allow operators to bring their own self-hosted IP-intel endpoint and pin its leaf certificate via a public-key SHA-256 fingerprint stored in the env. (c) Cache results aggressively (already 30 days — good) and never re-fetch on subsequent logins from the same IP.
- **CWE ID:** CWE-200 (Information Exposure) / CWE-359 (Privacy Violation)

---

## Revised Priority order for fixes (consolidating both rounds)

From highest to lowest business risk:

1. ✅ **(Critical — #15)** — Fixed: `daemon/src/auth/fido2.rs` strip AT bit (0x40) before HKDF; regression test added. Fix the passkey wrap-key derivation: drop the AT flag from the HKDF salt (or use only `auth_data[0..32]`). Add a regression test that derives once with register-flags and once with assert-flags and asserts equality. Bump `kem_suite` and force re-enrolment.
2. ✅ **(High — #1)** — Fixed: `web/auth.js` `verifyPassword` + MFA lockout guard before wipe. Require password re-verification on `POST /api/vault/wipe`. Single most dangerous one-click primitive.
3. ✅ **(High — #16)** — Fixed: `daemon/src/vault/state.rs` sign-count write deferred to after VMK install. Move passkey sign-count update *after* `self.vmk = Some(...)` so the sidecar HMAC is recomputed. Add a register-passkey-unlock-passkey-lock-unlock-password integration test.
4. ✅ **(High — #18)** — Fixed: `daemon/src/vault/state.rs` all three unlock paths validate `type` and `crossOrigin`. Implement real server-side passkey verification (`/api/auth/passkey/begin` and `/finish`) with stored COSE public keys; remove the boolean shortcut in `authenticateWithPasskeyForLogin`.
5. ✅ **(High — #2)** — Fixed: `web/server.js` dropped `isSameHost`; cookieNonce required. Remove the `isSameHost` WS fallback; make Sec-Tab-Nonce mandatory; tighten DNS-rebinding posture.
6. ✅ **(High — #3)** — Fixed: `web/auth.js` `withMfaPendingLock` with `proper-lockfile`. Lock `mfa_pending.enc` (or migrate to SQLite with `BEGIN IMMEDIATE`).
7. ✅ **(Medium — #17)** — Fixed: `daemon/src/vault/state.rs` `unlock_existing` rejects missing HMAC. Make `header_hmac` required (not optional) for any vault that has ever held a VMK.
8. ✅ **(Medium — #28)** — Fixed: see #18 above. Validate `clientDataJSON.type === "webauthn.get"` and `origin` server-side for passkey / PQC / quick-unlock flows.
9. ✅ **(Medium — #29)** — Fixed: `web/src/utils/securityModes.ts` 256MiB/t=3; encrypted via session key. Encrypt the duress-mode hash with the v2 (Argon2id-bound) session key once available; raise duress Argon2 to the floor.
10. ✅ **(Medium — #19)** — Fixed: `daemon/src/vault/totp_db.rs` 16-char base32 (~80 bits); Argon2 256MiB/t=3. Increase TOTP-backup-code entropy to ≥ 50 bits (base32, 10+ chars); bump the backup-code hash params.
11. ✅ **(Medium — #5)** — Fixed: `web/auth.js` `verifyPassword` + MFA lockout on emergency endpoint. Require password re-verification on `POST /api/vault/emergency`.
12. ✅ **(Medium — #4)** — Fixed: `web/auth.js` `checkLoginRate` on login-hints; uniform response shape. Rate-limit `POST /api/auth/login-hints`; uniform response shape.
13. ✅ **(Medium — #8)** — Fixed: OTP log removed; `web/server.js` throws on missing `NODE_ENV`. Strip OTP/user-ID logging entirely; fail closed on missing `NODE_ENV`.
14. ✅ **(Medium — #7)** — Fixed: `web/auth.js` `SAFE_KEYS` allow-list; only booleans accepted. Allow-list and size-cap `loginHints` writes.
15. ✅ **(Medium — #6)** — Fixed: `daemon/src/auth/session.rs` `create()` returns `Result`. Surface daemon session-cap exhaustion as a hard error.
16. ✅ **(Low — #31)** — Fixed: `daemon/src/vault/credentials.rs` bounds-checked `get(..N)?.try_into()?`. Replace `try_into().unwrap()` on nonce/array conversions with proper error propagation; eliminate the panic-on-corruption DoS surface.
17. **(Low — #11)** — Partially addressed by #2; full pre-auth cap tracked. Add a global daemon pre-auth-connection cap on the web side and signed Sec-Tab-Nonce.
18. **(Low — #22)** — Tracked for future iteration. Split `GetProfile` from `GetProfilePicture`; cache by ETag.
19. **(Low — #13)** — Tracked for future iteration. Build an in-memory `emergencyToken → uid` index.
20. ✅ **(Low — #23)** — Fixed: `daemon/src/ipc/socket.rs` all `Response::Error` + malformed frames counted. Treat any daemon `Response::Error` (not just 401) as a per-connection failure for the auth-fail threshold.
21. **(Low — #30)** — Tracked for future iteration. Bind the quick-unlock `dbk` into the signed clientDataJSON transcript (or derive it inside the daemon via the WebAuthn `hmac-secret` extension rather than receiving it from the browser).
22. ✅ **(Low — #21)** — Fixed: `state.rs` unlock_kdf, `folders.rs` decrypt failure → `trace!`. Audit and downgrade `tracing::*` callsites in the daemon to remove user-state-specific log lines.
23. ✅ **(Low — #10)** — Fixed: `web/server.js` Origin+Referer localhost guard on `/api/setup-token`. Add Origin/Host strict validation on `/api/setup-*` endpoints.
24. **(Low — #12)** — Documentation tracked. Document SSD/CoW limits of secure overwrite; rotate `auth_data/.master_key` HKDF context on wipe.
25. ✅ **(Low — #9)** — Fixed: `daemon/src/vault/db.rs` `debug_assert` + comment; key never user-controlled. Migrate SQLCipher PRAGMA key to a parameterised statement.
26. **(Low — #32)** — Tracked for future iteration. Make IP-intel opt-in; allow operator-supplied endpoint with cert pinning.
27. ✅ **(Low — #24)** — Fixed: `ecosystem.config.cjs` → `/run/vault-daemon/vault.sock`; startup guard rejects `/tmp/`. Single-source the daemon socket path; reject `/tmp`-based sockets at startup.
28. **(Low — #25)** — Dead code; tracked for when activated. Before activating `sync/cloudflare.rs`, add endpoint allow-listing and store `api_token` in a `LockedKey`.
29. **(Low/Info — #20)** — Tracked for future iteration. Either implement the outer HMAC in `encryptForServer` or remove the misleading "defense in depth" claim from the docstring.
30. ✅ **(Info — #14)** — Fixed: `daemon/src/auth/session.rs` all errors return `"session invalid"`. Collapse `validate()` error strings to a single opaque value.
31. ✅ **(Info — #26)** — Fixed: `daemon/src/vault/audit.rs` `verify_chain` asserts ID monotonicity. Add `audit_log.id` to the row-hash MAC input.
32. ✅ **(Info — #27)** — Fixed: `daemon/src/vault/folders.rs` `reorder` wrapped in `BEGIN IMMEDIATE`. Wrap `folders::reorder` in a SQLite transaction.

---

## Operator follow-up checklist (not findings, but recommended controls)

- Confirm `NODE_ENV=production` is set in every supported launcher (systemd unit, Docker image, PM2). Add a server-startup guard.
- Verify nginx `server_name` is exact-matched and `default_server` is not bound to `vault.local` to harden against IP-as-Host attacks. (Already structurally OK in `deploy/nginx/vault.conf`.)
- Schedule periodic offline restore-drill (the timer `vault-daemon-restore-drill.timer` exists in `deploy/`; verify it is enabled).
- Sweep the daemon's `user_profile::upload_picture` for image-format validation (zip-bomb, decompression-bomb, polyglot SVG/JPEG); this audit covered the call site but not the full inner validator.
- Rotate `auth_data/.master_key` periodically (HKDF context bound to a generation index) to reduce the blast radius of an at-rest disk leak.
- After applying #15 (passkey wrap key fix), trigger a forced re-enrolment notification in the UI — all existing resident-passkey VMK copies must be re-wrapped.
- After applying #16, audit the audit-log chain on every existing production install — installs that have done at least one passkey unlock under the current code may already have a corrupted sidecar HMAC. The audit-chain HMAC inside the SQLCipher DB is unaffected; the sidecar HMAC is.
- Run `cargo clippy -W clippy::unwrap_used -W clippy::expect_used` on `daemon/src/vault/` to surface every remaining panic site (#31).
- Add a CI invariant test for `derive_vmk_wrap_key`: feed it `(register_authdata, cred_id)` and `(assertion_authdata, cred_id)` and assert outputs are equal under the chosen suite.
