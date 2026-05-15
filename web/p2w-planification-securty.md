# PWDnow — Path to NIST PQC Level 5 ("L99") — Full Audit and Remediation Plan

> Status: Plan only. No code changes have been made under this document.
> The next prompt is the integration prompt; during integration, progress is
> tracked in `p2w-progress.md` so work can resume after an interruption
> without restarting from scratch.

---

## 0. Document control

| Field | Value |
|---|---|
| Document | `web/p2w-planification-securty.md` |
| Companion progress file | `web/p2w-progress.md` (created during integration) |
| Authoritative scope | Full PWDnow tree: `daemon/`, `web/`, `deploy/`, `hibp/` |
| Target posture | NIST PQC Level 5 for symmetric primitives, hybrid PQC Level 5 (X25519 + ML-KEM-1024 + Ed25519 + ML-DSA-87) for any asymmetric primitive that ships, plus best-practice memory hardness, sandboxing, and supply-chain integrity |
| Design rule | No emoji in code, comments, commit messages, or this document |
| Backwards-compat | Mandatory: existing v1 `.p2w` files keep importing; existing demo localStorage vaults keep decrypting; existing daemon DBs keep unlocking. Every breaking change ships behind a versioned format byte and a one-shot migration. |
| Out of scope | Cloud sync, multi-tenant sharing, mobile apps, recovery custodian networks |

### Glossary

- **L5 / Level 5**: NIST PQC Category 5. Any attack must require resources comparable to or greater than key search on AES-256. Symmetric: at least 256-bit classical, 128-bit quantum. Asymmetric (lattice KEM/sig): ML-KEM-1024, ML-DSA-87, FALCON-1024 or SLH-DSA-256s.
- **L99**: user shorthand for "the highest practical security we can credibly defend." Where L5 is the floor, L99 is the ceiling we aim for: hybrid-PQC, memory-hard KDFs at high parameters, hardware-backed keys, sandbox isolation, supply-chain attestation, runtime mitigations.
- **VMK**: Vault Master Key, 256-bit key that decrypts all per-credential DEKs. Lives only in mlock'd memory inside the daemon.
- **DEK**: Data Encryption Key. One per credential; encrypted with VMK in SQLCipher.
- **KEK**: Key-Encrypting Key derived from passphrase plus optional YubiKey HMAC via Argon2id; decrypts the encrypted VMK.
- **Sidecar**: `vault.db.meta`, plaintext JSON file the daemon reads before unlock.
- **Suite byte**: 1-byte `cipher_suite` identifier embedded in headers (e.g., `.p2w` byte 7).

---

## 1. Mission and definitions

### 1.1 Goal

Take every cryptographic boundary, persistence layer, transport, sandbox, and supply-chain step in the PWDnow codebase to a posture that an external auditor would label as NIST PQC Level 5 wherever the primitive is symmetric, and to a hybrid Level 5 PQC posture wherever any asymmetric primitive is used now or in the future. Where direct NIST classification does not apply (e.g., a systemd hardening directive, a CSP rule, a build-pipeline measure), the goal is the equivalent operational maximum.

### 1.2 What "Level 5" means in this codebase

| Primitive class | Currently | Target (Level 5) |
|---|---|---|
| Symmetric AEAD | AES-256-GCM, XChaCha20-Poly1305 | Same. Already L5. Keep both as cascade layers. |
| Hash | SHA-256, SHA-512, SHA3-512, BLAKE3 | Promote everything that protects a long-lived secret to SHA3-512 / SHAKE256. Keep BLAKE3 for performance-sensitive audit chain. Keep SHA-256 only for short-lived integrity (e.g., session-token hashing) where output truncation does not weaken anything. |
| HMAC | HMAC-SHA-512 (P2W v1), HMAC-SHA3-512 (P2W v2) | HMAC-SHA3-512 everywhere a long-lived secret is keyed. Already done in P2W v2. |
| Password KDF | Argon2id (256 MiB, t=3, p=4) | Argon2id (1 GiB, t=4, p=2) for the daemon master password; m=256 MiB minimum elsewhere. Auto-tune upward if hardware permits. |
| Server password hash | scrypt (N=2^17, r=8, p=1) | Replace with Argon2id (256 MiB, t=4, p=1). scrypt-N=2^20 acceptable as fallback. |
| KEM (asymmetric) | X25519 + ML-KEM-768 (feature-gated) | X25519 + ML-KEM-1024 hybrid, default-on, no feature flag. |
| Signatures | None on the wire | Where signatures are needed (passkey assertions, file-share authenticity, audit-log root): hybrid Ed25519 + ML-DSA-87; new wire-format byte selects the algorithm. |
| TLS | TLS 1.3 only, classical curves | TLS 1.3 with X25519MLKEM1024 hybrid key share (OpenSSL 3.4+, BoringSSL, or via nginx-plus / haproxy). |

### 1.3 Operational targets (non-cryptographic)

- **Sandboxing**: every daemon syscall, every file path, every kernel feature unused by the daemon must be denied at three layers (systemd, AppArmor, seccomp).
- **Supply chain**: SLSA Level 3, Sigstore signing of release artifacts, SBOM (CycloneDX), reproducible builds, `cargo audit` and `npm audit` in CI on every push.
- **Memory hygiene**: zeroize on every drop path, mlock for all live key material, swap disabled, coredumps disabled, ptrace_scope=2 on the host.
- **Anti-forensics**: 7-pass overwrite plus `BLKDISCARD` TRIM hint on SSDs, encrypted root filesystem (LUKS) recommended, browser local state purged on logout with multiple passes.
- **Side channels**: constant-time comparisons for every secret-keyed comparison, AES-NI verification at startup, fallback to constant-time ChaCha if AES-NI is absent on a server.

### 1.4 Out of scope

- Distributed / cloud sync (would require a new fan-out format).
- Custodian recovery networks (separate trust model).
- Mobile applications (separate codebase).
- Hardware Root of Trust integration (TPM2 / Secure Element). Listed as Phase H stretch goal but not blocking L5.

---

## 2. Threat model

### 2.1 Adversaries (in order of priority)

1. **Passive attacker with stolen `.p2w` file or `auth_data/` snapshot.** Has unlimited offline computing time. The dominant attack. Defended by KDF cost plus cipher strength.
2. **Active MITM on the LAN or coffee-shop Wi-Fi.** Defended by TLS 1.3 plus HSTS preload plus nginx config plus WebSocket origin pinning.
3. **Malware running as the same user as the browser or daemon.** Defended by SecureKeyStore private fields, mlock, AppArmor file deny rules, ptrace_scope=2, coredump=0.
4. **Evil-maid / cold-boot attacker with brief physical access.** Defended by full-disk encryption (operator deployment guidance), mlock, swap=0, zeroize on lock, host-firmware password.
5. **Post-quantum capable adversary.** Defended by symmetric L5 primitives, hybrid PQC asymmetric primitives, password KDF that is memory-hard not factorisation-hard.
6. **Supply-chain compromise** of an npm or crates.io dependency. Defended by pinned hashes, npm/cargo audit gates, SBOM, reproducible builds, Sigstore signatures, integrity checks at install time.
7. **Insider / lazy admin.** Defended by least-privilege systemd unit, no shared secrets in config, audit log per action, append-only audit chain (BLAKE3).
8. **Side-channel attacker (timing / cache / power).** Defended by constant-time crypto, AES-NI fallback, no compression-before-encryption, no plaintext-in-error-message oracles.
9. **Phishing / social-engineering of the user.** Defended by anti-phishing flow on login, distinct duress mode, training in user docs.
10. **TEMPEST / acoustic / EM emanations.** Out of practical scope; documented as accepted risk.

### 2.2 Trust boundaries

- **Browser to Express server**: HTTPS plus CSRF plus CSP nonce plus SameSite=Strict cookies plus Trusted Types.
- **Express server to Daemon**: Unix socket, msgpack frames, SO_PEERCRED check on every authenticated request, session token bound to UID.
- **Daemon to Disk**: AppArmor file ACL plus UID 0 cannot read vault.db without daemon assistance plus SQLCipher AES-256.
- **Daemon to Kernel**: systemd capability bounding plus seccomp filter plus namespace restrictions.

### 2.3 Assets ranked by sensitivity

| Asset | Sensitivity | Lifetime | Storage |
|---|---|---|---|
| Master passphrase | Critical | User-lifetime | Never persisted |
| VMK | Critical | Vault-unlock-lifetime | mlock'd RAM only |
| Per-credential DEK | Critical | Operation-lifetime | mlock'd RAM only |
| Session token | High | 15 min idle / 24 h absolute | SecureKeyStore (browser), session table (daemon) |
| Server scrypt hash | High | Account-lifetime | `auth_data/users.enc` |
| TOTP secret | High | Credential-lifetime | Encrypted DEK in SQLCipher |
| Audit log | Medium | Vault-lifetime | BLAKE3-chained, encrypted |
| Folder labels / URLs | Medium | Credential-lifetime | Encrypted |
| Vault DB filename, count | Low (metadata leak) | Vault-lifetime | Filesystem |

---

## 3. Current state inventory

### 3.1 Layer 1 — Daemon (`daemon/`, Rust)

| Aspect | Current state | Reference |
|---|---|---|
| Language / runtime | Rust 2021, tokio 1.51 | `daemon/Cargo.toml` |
| KDF | Argon2id m=256 MiB, t=3, p=4 | `daemon/src/crypto/argon2.rs:6-8` |
| AEAD | XChaCha20-Poly1305 (outer), AES-256-GCM (inner / OTP / DEK) | `daemon/src/crypto/{xchacha20.rs, aes_gcm.rs}` |
| KEM | X25519 + ML-KEM-768, hybrid via HKDF-SHA3-512, feature-gated | `daemon/src/crypto/kem.rs:113-219` |
| Hashes | SHA-256 (sessions, salts), SHA-512 (HKDF in fido2), SHA3-512 (KEM), BLAKE3 (audit chain) | various |
| Key zeroization | `zeroize` 1.8.2 used on KDF input, DEK, TOTP, KEM secrets | `argon2.rs:27`, `credentials.rs:61,83`, `totp_db.rs:44`, `kem.rs:160-202` |
| Secure key memory | `LockedKey` mmap+mprotect+mlock+zeroize | `daemon/src/crypto/secure_store.rs:1-140` |
| Session tokens | 32-byte hex, idle 900 s, abs 86 400 s, max 8/user, UID-bound | `daemon/src/auth/session.rs:9-114` |
| Brute-force lockout | `[0,0,0,0,0,30,60,120,300,600]` seconds at attempt index | `daemon/src/vault/state.rs:23-26` |
| Audit log | BLAKE3-chained inside SQLCipher | `daemon/src/vault/audit.rs:1-205` |
| IPC | msgpack frames over Unix socket, 4 MiB cap, SO_PEERCRED, no `deny_unknown_fields` | `daemon/src/ipc/{protocol.rs,socket.rs}` |
| ML-KEM crate | `ml-kem = "0.3.0-rc.2"` (release candidate) | `daemon/Cargo.toml:39` |
| Forensic wipe | 7-pass over sidecar plus db plus WAL plus SHM, no `BLKDISCARD` | `daemon/src/vault/state.rs::shred_path` |
| FIDO2 | libfido2 via FFI, ~150 lines `unsafe` (justified) | `daemon/src/auth/fido2.rs` |
| Mock-FIDO2 | gated via `#[cfg(any(test, feature = "mock-fido2"))]`, default off | `daemon/Cargo.toml:50-56` |

### 3.2 Layer 2 — Web server (`web/server.js`, `web/auth.js`, Node.js)

| Aspect | Current state | Reference |
|---|---|---|
| Server password hash | scrypt N=2^17, r=8, p=1, len=64, maxmem=256 MiB | `auth.js:18-22, 125-126` |
| JWE sessions | dir / A256GCM, 24 h abs, 15 min rolling | `auth.js:24-25, 145-166` |
| CSRF | `_pwd_csrf` cookie plus `X-CSRF-Token` header | `auth.js:172, 205-214` |
| Cookies | HttpOnly plus Secure (cond) plus SameSite=Strict | `auth.js:171-172` |
| File-at-rest | AES-256-GCM with HKDF-SHA-256 key per file | `auth.js:56-82` |
| Master key | 32 bytes random, mode 0o400 at `auth_data/.master_key` | `auth.js:37-54` |
| CSP (set in Express) | nonce on script, `'unsafe-inline'` on style for Tailwind | `server.js:100-126` |
| HSTS | 1 year, includeSubDomains, preload | `server.js:127-137` |
| WebSocket | origin allow-list (env plus hardcoded), no `maxPayload` on `ws.Server`, no per-IP reconnect throttle | `server.js:359-437` |
| Setup token | localhost-only via socket addr plus X-Real-IP, single-use sentinel | `server.js:47-88, 221-237` |
| `system-info` endpoint | leaks kernel, hostname, CPU, TPM, HSM, FIPS, disk-cipher | `server.js:248-260` plus script |
| Login rate limit | None at app level, nginx `auth_limit` defined but commented out | `auth.js`, `deploy/nginx/vault.conf:108-116` |
| 2FA enforcement | client-side flags only, server does not gate JWE issuance on MFA verification | `auth.js:441-452` |
| JTI invalidation on password change | Not done | `auth.js:561` |
| Decryption fallback | If `auth_data/<uid>/*.enc` decryption fails, silently treated as plaintext JSON | `auth.js:594-599` |

### 3.3 Layer 3 — Web client (`web/src/`, React 19)

| Aspect | Current state | Reference |
|---|---|---|
| `SecureKeyStore` | session token in private `#token` field, cleared on `pagehide` / `visibilitychange` / `logout` | `web/src/crypto/keystore.ts` |
| Local KDF | PBKDF2-SHA-256, 310 000 iterations, single pass, AES-256-GCM plus HMAC-SHA-256 | `keystore.ts:97`, `localCrypto.ts` |
| Demo / offline encryption | AES-256-GCM via WebCrypto (XChaCha fallback only on plain HTTP for travel) | `localCrypto.ts:73-92`, `securityModes.ts:264-265` |
| TOTP | HMAC-SHA-1, 6 digits, 30 s, in-memory replay set | `mfa.ts:12, 276, 331-360` |
| HOTP | counter persisted, lookahead 10 | `mfa.ts:317` |
| Email OTP | 6 digits via `crypto.getRandomValues`, 5 min TTL, single-use | `mfa.ts:382-398` |
| WebAuthn | challenge 32 B random, residentKey discouraged for hw keys | `mfa.ts:512, 547-572` |
| Passkey | residentKey true, hint stored encrypted in localStorage | `mfa.ts:592` |
| Duress mode | plaintext salt+hash, hash via `timingSafeHash` (XOR loop), max attempts default 5 | `securityModes.ts:47, 160-205` |
| Travel mode | PBKDF2 120 000 iters, AES-GCM, hidden vault is a separate blob | `securityModes.ts:241-299` |
| Forensic wipe (browser) | 3-pass CSPRNG over localStorage values plus clear localStorage plus sessionStorage plus IndexedDB plus caches | `securityModes.ts:101-141` |
| Trusted Types | default policy in `main.tsx`; `createScript` blocked, `createScriptURL` allows only `/sw.js` | `main.tsx:19-28` |
| CSV importers | quote-aware parser, no prototype pollution surface | `importExport.ts:76-95` |
| Filename on export | passed verbatim to `<a download>`, no path-injection check | `importExport.ts:923` |
| Service worker | VitePWA with locales-only CacheFirst; `/api/`, `/ws`, `/share/` denied | `vite.config.ts:14-34` |
| `.p2w` format | suite 0x02 (Argon2id m=256 MiB t=3 p=1, HKDF-SHA3-512, AAD-bound double AEAD, HMAC-SHA3-512); v1 import-only with bounds | `web/src/utils/p2wFormat.ts`, `web/P2W_FORMAT.md` |

### 3.4 Layer 4 — Deploy (`deploy/`)

| Aspect | Current state | Reference |
|---|---|---|
| Nginx TLS | TLS 1.3 only, explicit cipher list, OCSP stapling on, no PQC hybrid key share | `deploy/nginx/vault.conf:28-53` |
| Nginx headers | HSTS, XFO=deny, XCTO, Referrer-Policy, COOP, CORP, Permissions-Policy. No COEP. | `vault.conf:61-72` |
| Nginx limits | `general_limit 300/m`, `auth_limit 5/m` defined but not applied, `client_max_body_size 4m` | `vault.conf:14-17, 43, 108-116` |
| systemd unit | NoNewPrivileges, ProtectSystem=strict, ProtectHome=read-only, RestrictNamespaces, SystemCallFilter on system-service plus memlock, Cap=`CAP_IPC_LOCK`, MemorySwapMax=0 | `deploy/vault-daemon.service:1-43` |
| systemd missing | MemoryDenyWriteExecute, RestrictAddressFamilies, LockPersonality, RemoveIPC, ProtectKernelLogs/Tunables/Modules/Clock/Hostname, ProtectProc, PrivateTmp/Devices/Users, RestrictRealtime, RestrictSUIDSGID, MemoryMax/CPUQuota/TasksMax, UMask, ReadWritePaths | n/a (omission) |
| AppArmor | enforce mode, glob libpath (works on x86_64 plus aarch64), denies network plus /proc/*/mem plus /etc/{shadow,passwd} plus /root | `deploy/apparmor.d/vault-daemon` |
| Container | No Dockerfile present | `deploy/` |

### 3.5 Layer 5 — Build and supply chain

| Aspect | Current state | Reference |
|---|---|---|
| Vite | sourcemap off in prod, manual chunks, no API keys baked in | `vite.config.ts` |
| package-lock.json | present, integrity hashes by default | `web/package-lock.json` |
| npm audit | not in CI | n/a |
| cargo audit | not in CI | n/a |
| Reproducible build flags | none configured | n/a |
| SBOM | none | n/a |
| Sigstore signing of releases | none | n/a |
| SLSA provenance | none | n/a |

---

## 4. Findings catalogue

Each finding has: **ID** (layer-prefix plus ordinal), **Severity** (CRIT / HIGH / MED / LOW), **Title**, **Evidence**, **What L5 requires**, **Fix sketch**. The full implementation detail is deferred to Section 6 to keep this catalogue scannable.

Severity definitions (specific to this audit):

- **CRIT**: a credible, presently-feasible attack that defeats a stated security guarantee. Must be fixed before claiming L5.
- **HIGH**: a credible attack within plausible adversary capability, or a structural gap that defeats defence-in-depth. Must be fixed for L5.
- **MED**: a hardening gap that increases attack surface or reduces resilience but is not an immediate full break.
- **LOW**: hygiene / documentation / metadata leak / future-proofing.

### 4.1 Daemon (`D-*`)

| ID | Sev | Title | Evidence | L5 requires | Fix |
|---|---|---|---|---|---|
| D-01 | CRIT | ML-KEM-768 instead of ML-KEM-1024 | `kem.rs:113-219`, `Cargo.toml:39` | ML-KEM-1024 for L5 | New cipher_suite for hybrid X25519+ML-KEM-1024; default-on; old suite remains for read-only migration |
| D-02 | CRIT | ML-KEM crate is `0.3.0-rc.2` (release candidate) | `Cargo.toml:39` | Stable, audited crate | Pin to a stable `ml-kem` release and `cargo audit` clean; consider `pqcrypto-mlkem` as alt |
| D-03 | HIGH | Argon2id parameters borderline for L5 (m=256 MiB, t=3, p=4) | `argon2.rs:6-8` | m at least 1 GiB, t at least 4 for master password, or auto-tuned | Auto-tune at install time targeting 1 second on the host; minimum m=1 GiB / t=4 / p=2 for the daemon master, m=256 MiB / t=3 / p=1 for hot paths |
| D-04 | HIGH | `pq` feature is opt-in; default builds use classical X25519 only | `Cargo.toml:51`, `kem.rs:223-230` | Hybrid PQC default-on | Make `pq` part of `default = ["pq"]`; rename to `pq-hybrid`; produce non-PQ build only via explicit opt-out |
| D-05 | HIGH | SQLCipher PRAGMAs not explicitly set | none, silent default | Explicit cipher = AES-256, kdf_iter at least 256 000, page_size = 4096, MAC = HMAC-SHA-512 | Set PRAGMAs in `daemon/src/db.rs::open_vault` and assert via test |
| D-06 | HIGH | msgpack `Request`/`Response` lack `serde(deny_unknown_fields)` attribute | `protocol.rs:16, 279` | Strict schema | Add attribute, add round-trip test that rejects extra fields |
| D-07 | HIGH | No `BLKDISCARD` / TRIM hint after forensic wipe | `state.rs::shred_path` | Best-effort SSD secure-erase | Add ioctl BLKDISCARD on the underlying block range; document SSD limits in security guide |
| D-08 | HIGH | Session token has no rotation on activity | `session.rs:107-114` | Sliding rotation window | Issue fresh token on every authenticated call, deprecate the old one in 60 s grace |
| D-09 | MED | LOCKOUT only per-UID, no per-IP / per-connection cap | `state.rs:23-26` | Per-process and per-connection limits | Add per-connection failed-attempt counter; cap concurrent unlocks |
| D-10 | MED | Session token revocation list absent | `session.rs` | Revoked tokens cannot be replayed | Add a revoked set persisted to disk for the revocation TTL window |
| D-11 | MED | Failed unlock attempts not in audit log | `audit.rs` | Append-only audit of all auth events | Log `UNLOCK_FAILED` with sanitised metadata |
| D-12 | MED | Audit log timestamp is seconds-precision | `audit.rs:26` | Microsecond-precision monotonic | Migrate to `u128` ns plus monotonic source |
| D-13 | MED | HKDF info labels mix SHA-256 (KEM step) and SHA3-512 (hybrid) | `kem.rs:104, 213` | Single hash family | Promote all KEM HKDF to SHA3-512 |
| D-14 | MED | release builds with opt-level 3 plus fat LTO | `Cargo.toml:59-63` | Tradeoff vs side-channel risk | Move crypto crates to opt-level 2 profile override; verify no perf regression |
| D-15 | LOW | Tracing macros may log at debug level | none confirmed | No secrets in logs at any level | Add a clippy lint or doc-grep that fails CI on tracing debug patterns containing the word password |
| D-16 | LOW | Passkey challenge stored in `Mutex<Option<[u8;32]>>` | `state.rs::passkey_challenge` | Constant-time consume | Already `take()`-based, but hash of expected challenge would tighten audit |
| D-17 | LOW | Tokio MIO frame parser has no fuzz target | none | Fuzz coverage in CI | Add `cargo-fuzz` target for `parse_frame` |

### 4.2 Web server / auth (`S-*`)

| ID | Sev | Title | Evidence | L5 requires | Fix |
|---|---|---|---|---|---|
| S-01 | CRIT | 2FA not enforced server-side; client may skip | `auth.js:441-452` | Server validates the second factor before issuing JWE | Add MFA challenge endpoint, gate `loginComplete` on signed challenge response |
| S-02 | CRIT | `auth_data/<uid>/*.enc` decryption failure leads to silent plaintext-JSON fallback | `auth.js:594-599` | Hard fail on integrity violation | Remove fallback; on integrity failure, surface a recovery prompt and audit log entry |
| S-03 | CRIT | `MemoryDenyWriteExecute` absent from systemd unit | `vault-daemon.service` | W xor X enforced | Add directive |
| S-04 | CRIT | `system-info` endpoint leaks kernel, hostname, CPU, TPM, HSM, FIPS, disk-cipher | `server.js:248-260` | Setup-flow only, host-anonymous | Restrict to setup phase pre-completion; redact hostname; behind setup token |
| S-05 | HIGH | scrypt instead of Argon2id for server password | `auth.js:18-22, 125` | Argon2id memory-hard for L5 | Add Argon2id rehash-on-login path; new accounts use Argon2id; legacy scrypt verified once then upgraded transparently |
| S-06 | HIGH | No login rate limit at app or nginx level (rules commented out) | `auth.js`, `vault.conf:108-116` | Per-IP and per-account rate limits | Apply `auth_limit` to `/api/auth/login`, `/api/auth/2fa/verify`, `/api/auth/forgot-password`; add app-level token bucket per-username with exponential back-off |
| S-07 | HIGH | JTIs not invalidated on password change | `auth.js:561` | All sessions revoked on credential change | Mark all of user's JTIs revoked atomically; respond 401 next request |
| S-08 | HIGH | WebSocket lacks `maxPayload` cap, allows up to 100 MiB | `server.js:359-437` | Aligned with daemon's 4 MiB | Set `maxPayload: 4 * 1024 * 1024` on `WebSocketServer` constructor |
| S-09 | HIGH | WebSocket reconnect not throttled per-IP | `server.js:359-437` | Connection-rate cap | Track recent connect counts per peer IP, drop with 1013 after threshold |
| S-10 | HIGH | `style-src 'unsafe-inline'` (Tailwind) | `server.js:100-126` | Hash-based or no-inline styles | Switch to compile-time-only Tailwind output, drop the unsafe-inline directive |
| S-11 | HIGH | Master key has no rotation policy | `auth.js:37-54` | Rotation procedure documented and automated | HKDF-derived per-resource key plus a master KEK rotation playbook; add monthly cron-friendly rotate command |
| S-12 | MED | `express.json()` default body limit (100 KB) clashes with nginx 4 MiB | `auth.js:141`, `vault.conf:43` | Aligned, deliberate | Set explicit `express.json({ limit: '512kb' })` per route; oversized vault uploads use a chunked endpoint |
| S-13 | MED | systemd missing many hardening directives | `vault-daemon.service` | Full L5 sandbox profile | See section 6.4; add ProtectKernelLogs/Tunables/Modules/Clock/Hostname, RestrictAddressFamilies=AF_UNIX, LockPersonality, RemoveIPC, PrivateTmp, RestrictRealtime, RestrictSUIDSGID, ProtectProc=invisible, ProcSubset=pid, NoExecPaths, MemoryMax, CPUQuota, TasksMax, LimitNOFILE, UMask=0077, ReadWritePaths to /var/lib/vault-daemon and /run/vault-daemon |
| S-14 | MED | Nginx has no PQC TLS hybrid key share | `vault.conf:28-53` | X25519MLKEM1024 hybrid | Document upgrade path to nginx with OpenSSL 3.4+ or BoringSSL; add `ssl_conf_command Groups X25519MLKEM1024:X25519:secp256r1` |
| S-15 | MED | Recovery key has no expiry | `auth.js:502-522` | Rotated periodically | Add `recoveryKeyExpiresAt`, force re-issue on a cadence |
| S-16 | MED | No SRI on script tags in dist/index.html | `dist/index.html` | SRI as belt-and-braces with CSP nonce | Generate SRI hashes in build, inject in template |
| S-17 | MED | No COEP header | `server.js`, `vault.conf` | Cross-Origin-Embedder-Policy: require-corp | Add to Express headers |
| S-18 | MED | OCSP stapling references commented `ca-chain.pem` path | `vault.conf:48` | Stapling functional in production | Document operator step; verify in deploy script |
| S-19 | LOW | Audit log per user trimmed to 1000 entries (sliding window) | `auth.js:321` | Append-only, retained until rotation | Add log rotation file rather than truncation; keep tamper chain |
| S-20 | LOW | No Dockerfile for reproducible deploy | `deploy/` | Distroless multi-stage build | Add `deploy/Dockerfile` with distroless `cc` for daemon and distroless `nodejs20` for server |

### 4.3 Web client / browser (`C-*`)

| ID | Sev | Title | Evidence | L5 requires | Fix |
|---|---|---|---|---|---|
| C-01 | HIGH | Travel-mode KDF uses 120 000 PBKDF2 iters (vs 310 000 for local) | `securityModes.ts:241-247` | Argon2id-equivalent or matching iteration count | Switch travel-mode KDF to Argon2id (browser via `@noble/hashes/argon2`); fall back to PBKDF2 600 000 only on plain HTTP |
| C-02 | HIGH | Duress hash stored in plaintext localStorage | `securityModes.ts:47, 160-166` | Argon2id'd or KEK-encrypted | Encrypt the hash with the demo-mode local key, or store only an Argon2id PHC string |
| C-03 | HIGH | TOTP uses HMAC-SHA-1 | `mfa.ts:12, 276` | SHA-256 or SHA-512-HMAC for new credentials | Add TOTP algorithm field to the `Credential` type; default new credentials to SHA-256; legacy SHA-1 supported for read |
| C-04 | HIGH | Login hints (passwordEnabled, totp, webauthn) sent client-side without freshness check | `mfa.ts::refreshLoginHints` | Per-attempt server-signed hints | Server signs hints with rotating key; client verifies signature before display |
| C-05 | MED | Filename on export not sanitised against path-injection in download attribute | `importExport.ts:923` | RFC 5987 plus basename only | Strip path separators, normalise NFC, enforce extension whitelist |
| C-06 | MED | Local KDF is PBKDF2-SHA-256 310 000 iters | `keystore.ts:97` | Argon2id with m at least 256 MiB | Migrate to Argon2id; bump LocalCryptoEnvelope to v2 with header byte indicating KDF; legacy v1 reads transparently |
| C-07 | MED | Email OTP truncates 32-bit RNG to 6 digits | `mfa.ts:382` | Direct uniform sampling 0..999999 | Use rejection sampling on `Uint32Array` to avoid modulo bias |
| C-08 | MED | Passkey credential ID hint encrypted in localStorage but key derivation TTL unbounded | `mfa.ts:592` | TTL on every cached secret | Add `expiresAt` to hint, drop after 30 d |
| C-09 | MED | The React innerHTML-bypass attribute is used in 7 places, all sanitised, but no CSP-trusted-types lint in CI | `src/**/*.tsx` | CI fails on unsanitised innerHTML | Add eslint rule `react/no-danger` with allowlist plus custom rule asserting `sanitizeSvg` upstream |
| C-10 | MED | Demo-mode encryption uses AES-GCM with 12 B random IV; format header is single byte | `localCrypto.ts:6-8, 76` | AAD-bound plus version field per item | Promote header to versioned struct; bind storage-key-name as AAD |
| C-11 | LOW | `crypto.subtle` returns non-extractable CryptoKey, but reference held in module | `keystore.ts:104-107` | Best practical | Wrap in WeakRef or scope-bound holder when feasible |
| C-12 | LOW | Service worker caches locales; no integrity check on cached payload | `vite.config.ts:14-34` | Optional Subresource Integrity in SW | Add SHA-256 verification before serving cached translation file |
| C-13 | LOW | Share-view URL fragment readable to script before navigation | `ShareView.tsx:82` | Mitigated by browser scope | Document; add `Cache-Control: no-store` server-side |

### 4.4 Deploy / sandbox / supply-chain (`X-*`)

| ID | Sev | Title | Evidence | L5 requires | Fix |
|---|---|---|---|---|---|
| X-01 | HIGH | No SBOM, no Sigstore, no SLSA provenance | n/a | Required for L5 supply chain | Add `cyclonedx-bom` for npm plus `cyclonedx-cargo` for Rust; sign release tarballs with `cosign`; publish provenance |
| X-02 | HIGH | `cargo audit` and `npm audit` not in CI | n/a | Block builds on known CVE | Add to CI; allow-list with rationale |
| X-03 | HIGH | Reproducible builds not configured | n/a | Bit-identical for the same input | Add `RUSTFLAGS` for stripping symbols, single codegen unit, fixed `SOURCE_DATE_EPOCH`, locked Node version, `npm ci --strict-peer-deps`, document on the build host |
| X-04 | MED | AppArmor profile glob may load unintended `.so` | `apparmor.d/vault-daemon` | Pin to a curated set | List specific filenames; add `audit deny @{PROC}/sys/kernel/random/uuid r,` |
| X-05 | MED | systemd no `seccomp` syscall allow-list expansion documentation | `vault-daemon.service` | Custom syscall filter narrower than `@system-service` | Curate via `strace -fc -e trace=...` during integration tests; emit minimal `SystemCallFilter` |
| X-06 | LOW | No host-side recommendation for `kernel.yama.ptrace_scope=2`, `kernel.kptr_restrict=2`, `vm.swappiness=0`, swap off | `deploy/` docs | Operator documentation | Add `deploy/host-hardening.md` |

---

## 5. Phased remediation roadmap

The work is grouped into 8 phases. Phases A through G must complete to claim L5; H is a stretch. Each phase has an estimated effort, dependencies, exit criteria, and the affected findings list.

### Phase A — Symmetric crypto baseline lock-in (1-2 days)

Finalises the symmetric posture so it is defensible as L5 before any asymmetric work.

- **A.1** Replace server-side scrypt with Argon2id m=256 MiB, t=4, p=1; add transparent rehash-on-login for legacy users. Touches: `web/auth.js`. Owner-finding: S-05.
- **A.2** Auto-tune Argon2id at daemon install time, target ~1 s on the host; persist tuned params in sidecar so unlock matches what was used at install. Touches: `daemon/src/crypto/argon2.rs`, `daemon/src/vault/state.rs`. Owner-finding: D-03.
- **A.3** Add browser-side Argon2id KDF for `localCrypto.ts` (LocalCryptoEnvelope v2). Read v1 transparently; write v2 by default. Touches: `web/src/utils/localCrypto.ts`, `web/src/crypto/keystore.ts`. Owner-finding: C-06.
- **A.4** Migrate travel-mode KDF to Argon2id (m=64 MiB, t=2, p=1) where SubtleCrypto plus WASM Argon2 are available; otherwise PBKDF2 600 000. Touches: `web/src/utils/securityModes.ts`. Owner-finding: C-01.
- **A.5** Migrate duress-mode hash to Argon2id PHC string format encrypted with the demo-mode local key. Touches: `web/src/utils/securityModes.ts`. Owner-finding: C-02.
- **A.6** Default new TOTP credentials to HMAC-SHA-256 plus 8 digits; preserve SHA-1 read for existing credentials. Touches: `web/src/utils/mfa.ts`, `web/src/types.ts`. Owner-finding: C-03.
- **A.7** Set explicit SQLCipher PRAGMAs at vault open: `cipher = aes-256-cbc`, `kdf_iter = 256000`, `page_size = 4096`, `cipher_use_hmac = ON`, `cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512`. Touches: `daemon/src/db.rs`. Owner-finding: D-05.

**Exit criteria**: A new vault created on this branch yields Argon2id everywhere a passphrase is involved; legacy reads still work; integration tests pass on both legacy and migrated stores.

### Phase B — PQC asymmetric upgrade (3-5 days)

Brings every asymmetric primitive to hybrid Level 5.

- **B.1** Add cipher-suite `0x02` to the daemon KEM module: hybrid `X25519 + ML-KEM-1024`, HKDF-SHA3-512 with info `vault-hybrid-kem-v2-mlkem1024`. Touches: `daemon/src/crypto/kem.rs`, `daemon/src/vault/state.rs`. Owner-finding: D-01.
- **B.2** Pin `ml-kem` to the first stable release (or vendored from `pqcrypto-mlkem`); confirm cargo-audit clean. Owner-finding: D-02.
- **B.3** Default `Cargo.toml` features include `pq`. Build profile `--no-default-features` produces a non-PQ binary. Update `Makefile`. Owner-finding: D-04.
- **B.4** When a signature is produced (passkey assertion, share-token integrity, audit-log root signing), use hybrid Ed25519 + ML-DSA-87; new wire-format byte selects the algorithm. Touches: `daemon/src/auth/`, new `daemon/src/crypto/sign.rs`.
- **B.5** Update P2W spec with optional suite 0x03: a `.p2w` recipient-encrypted variant where the file key is wrapped via X25519+ML-KEM-1024 to a recipient public key. Documented; implementation deferred to Phase H.

**Exit criteria**: New daemon binaries default to hybrid PQC unlocking; an interoperability test imports a v2 vault produced under classical-only build and re-encrypts it under hybrid.

### Phase C — IPC / protocol hardening (1-2 days)

- **C.1** Add `serde(deny_unknown_fields)` on every `Request`/`Response` variant; round-trip test rejecting trailing garbage. Owner-finding: D-06.
- **C.2** Implement session-token sliding rotation: every authenticated call returns a fresh token; old token usable for 60 s grace window. Owner-finding: D-08.
- **C.3** Persist a small revoked-token set keyed by JTI hash for the absolute-TTL window. Owner-finding: D-10.
- **C.4** Per-connection failed-attempt counter capped at 3; after the cap, drop and add IP to a 60-s greylist. Owner-finding: D-09.
- **C.5** Add `UNLOCK_FAILED`, `UNLOCK_LOCKOUT_ENTERED`, `UNLOCK_LOCKOUT_EXITED` events to audit log with sanitised metadata. Owner-finding: D-11.
- **C.6** Promote audit-log timestamps to nanosecond precision via `std::time::SystemTime` plus monotonic counter. Owner-finding: D-12.

**Exit criteria**: a test that submits a `Request` with extra fields fails closed; a test that replays a revoked token gets `Response::Error("session expired")`; failed unlock visible in audit chain.

### Phase D — Server-side hardening (2-3 days)

- **D.1** Server-side MFA enforcement: all `/api/auth/login` paths return a partial token; only after `/api/auth/2fa/verify` does the server issue a full JWE session cookie. Owner-finding: S-01.
- **D.2** Remove plaintext-JSON fallback in vault file readers; on integrity failure, return a recovery prompt and audit. Owner-finding: S-02.
- **D.3** Apply nginx `auth_limit` to `/api/auth/login`, `/api/auth/forgot-password`, `/api/auth/2fa/verify`. Add app-side token bucket per-username. Owner-finding: S-06.
- **D.4** On password change, atomically invalidate all of user's JTIs. Owner-finding: S-07.
- **D.5** Set `maxPayload: 4 * 1024 * 1024` on the WebSocket server, plus per-IP reconnect throttle. Owner-findings: S-08, S-09.
- **D.6** Lock `system-info` endpoint behind setup-token plus redact hostname/CPU/microarchitecture. Owner-finding: S-04.
- **D.7** Drop `'unsafe-inline'` from `style-src`. Inline-Tailwind extraction at build time, plus per-component `.css` modules. Owner-finding: S-10.
- **D.8** Add `Cross-Origin-Embedder-Policy: require-corp` and align CORP with COEP. Owner-finding: S-17.
- **D.9** Generate SRI hashes for all script chunks at build time; inject into HTML template. Owner-finding: S-16.
- **D.10** `express.json({ limit: '512kb' })` per route; chunked upload endpoint for vault imports >512 KiB. Owner-finding: S-12.
- **D.11** Master-key rotation tooling: HKDF-info adds a key-version prefix; rotate command re-wraps every encrypted file. Recovery-key TTL added. Owner-findings: S-11, S-15.

**Exit criteria**: `npm run lint` plus `npm run test` plus `npx playwright test` pass; a Burp / proxy test confirms 2FA gate cannot be bypassed; CSP report-only run shows zero `'unsafe-inline'` violations.

### Phase E — Sandboxing and deployment (1-2 days)

- **E.1** Expand systemd unit with the missing directives (full block in section 6.4). Owner-findings: S-13, S-03.
- **E.2** Add ioctl BLKDISCARD after the 7-pass overwrite in `shred_path`. Owner-finding: D-07.
- **E.3** Add a curated AppArmor library list (specific `.so` filenames where possible, glob only for arch suffix). Owner-finding: X-04.
- **E.4** Add a hand-tuned `SystemCallFilter=` list distilled from a strace run during integration tests; reject all others. Owner-finding: X-05.
- **E.5** Document host hardening in `deploy/host-hardening.md`: `kernel.yama.ptrace_scope=2`, `kernel.kptr_restrict=2`, `vm.swappiness=0`, swap off, FDE LUKS, BIOS password. Owner-finding: X-06.
- **E.6** `deploy/Dockerfile` (multi-stage, distroless) for both the daemon and the Express server. Owner-finding: S-20.
- **E.7** Document nginx PQC TLS hybrid key share rollout. Owner-finding: S-14.

**Exit criteria**: `systemd-analyze security vault-daemon.service` shows score at least 9.5 / 10; AppArmor profile passes `aa-enforce` and `aa-status` shows correct mode; `docker build .` produces an image smaller than 80 MiB and runs.

### Phase F — Supply chain (1-2 days)

- **F.1** Add `cargo audit` and `npm audit` to CI; gate on `high` and above; allowlist explicit. Owner-finding: X-02.
- **F.2** Generate CycloneDX SBOMs for both Rust and npm trees in CI; publish as build artifact. Owner-finding: X-01.
- **F.3** Sign release tarballs with `cosign` (Sigstore keyless); publish `*.sig` and `*.cert`. Owner-finding: X-01.
- **F.4** Configure reproducible Rust builds (`SOURCE_DATE_EPOCH`, RUSTFLAGS for codegen-units=1 plus strip=symbols plus metadata empty); document Node and npm version pin. Owner-finding: X-03.
- **F.5** Add `package-lock.json` integrity gate (`npm ci --strict-peer-deps`).
- **F.6** SLSA Level 3 GitHub Actions: builder pinned by digest, attestation generated.

**Exit criteria**: `cosign verify-blob --certificate ... --signature ... <release>.tar.gz` succeeds; SBOM lists every transitive dep with version and license; reproducible build run twice on different hosts produces identical hashes.

### Phase G — Testing and validation (3-5 days)

- **G.1** Property-based tests for the TLV parser, KEM encapsulation, AEAD round-trip via `proptest`.
- **G.2** `cargo-fuzz` targets for `parse_frame` (msgpack), `parsePayload` (P2W), `decrypt_credential`. Owner-finding: D-17.
- **G.3** Differential test: import plus export round-trip across all formats (`pwdnow-p2w`, `pwdnow-json-enc`, `bitwarden`, `1password`, `nordpass`).
- **G.4** Side-channel: `dudect` measurement on `timingSafeEq` and SQLCipher key check. Document baseline.
- **G.5** Negative tests: replay a session token, replay a passkey challenge, replay a recovery code. All must fail.
- **G.6** Adversarial integration test: a hand-crafted `.p2w` with `cipher_suite=0xAA`, `kdf_iters=0xFFFFFFFF`, oversized payload — must reject with the canonical FAIL message.
- **G.7** Penetration-test pass with Burp Suite plus ZAP; record findings; fix or accept-with-rationale.

**Exit criteria**: every public test runs in CI green; `cargo fuzz run parse_frame` survives 10^6 inputs without crash; Playwright e2e exercises duress, travel, lockout, forensic wipe, recovery.

### Phase H — Stretch goals (deferred)

- **H.1** TPM2 sealing of the daemon master key (Linux `tpm2-tss`).
- **H.2** Hardware Security Module (HSM) plug-in (PKCS#11) for enterprise deployments.
- **H.3** P2W suite `0x03`: recipient-encrypted exports via X25519+ML-KEM-1024 hybrid.
- **H.4** Audit-log root signed nightly with hybrid Ed25519+ML-DSA-87.
- **H.5** Browser passkey export via WebAuthn Level 3 conditional UI.
- **H.6** External pentest (third-party) and crypto review.

---

## 6. Per-finding implementation detail (load-bearing items only)

This section turns the table entries into prose precise enough to start coding without re-deriving the design. Lower-severity items are folded into the relevant phase notes in section 5.

### 6.1 D-01 / D-04 — Hybrid X25519 plus ML-KEM-1024, default-on

**Where**: `daemon/src/crypto/kem.rs`, `daemon/Cargo.toml`, `daemon/src/vault/state.rs::passkey_credentials`, `web/src/utils/daemonClient.ts`.

**What changes**:

- New `KemSuite::HybridXMlKem1024` variant alongside the existing 768.
- `Cargo.toml`: `default = ["pq-hybrid-1024"]`, with `"ml-kem" = "0.3.x"` (replace rc with stable; if stable not available, keep rc but pin commit hash).
- HKDF info label: `b"vault-hybrid-kem-v2-mlkem1024"` so the new suite cannot be confused with the old.
- Sidecar field `kem_suite: u8` records which suite was used to wrap the VMK; the daemon dispatches based on that byte.
- Re-wrap migration: on unlock under the legacy suite, the daemon optionally re-wraps the VMK under the new suite before issuing the session token. Behind a one-time flag `migrate_kem_suite_on_unlock = true`; logged in audit.

**Backwards compat**: old vaults remain importable indefinitely; new vaults default to the 1024 suite; mixed-suite operation is supported during migration window.

### 6.2 D-03 / A.2 — Auto-tuned Argon2id

**Where**: new `daemon/src/crypto/argon2_tune.rs`; called once during `init` / `set_password`.

**What changes**:

- Run a binary search over `t` between 3 and 16 with `m = 1 GiB, p = 2`, target wall-clock `1.0 s plus or minus 0.2 s`.
- Persist tuned `(m, t, p)` in sidecar.
- Refuse to load if persisted params would push current host above 5 s (avoid DoS-by-laptop on a Raspberry Pi reading a desktop's vault).
- Document override env var for CI: `PWDNOW_ARGON2_FAST=1` selects `(64 MiB, 1, 1)` for tests.

### 6.3 S-01 — Server-side MFA enforcement

**Where**: `web/auth.js` `/api/auth/login`, new `/api/auth/login/finish`, `web/src/pages/Login.tsx`.

**Sequence**:

1. Client posts username plus password to `/api/auth/login`.
2. Server validates password via Argon2id (Phase A.1).
3. If account has MFA, server responds `200 { partialToken, methods: ["totp", ...] }`.
4. Client posts `partialToken` plus MFA proof to `/api/auth/login/finish`.
5. Server verifies; on success issues full JWE session cookie plus CSRF cookie.

**Partial token**: 32-byte random, 5 min TTL, single-use, key-bound to user-id; stored in a tiny in-memory map keyed by token hash. Cleared on success or expiry.

**Backwards compat**: clients that POST to `/api/auth/login` and receive `partialToken` adapt to the two-step flow; pre-update clients that ignore the partialToken and try CSRF-protected calls will hit 401, prompting login retry.

### 6.4 S-13 / S-03 / E.1 — systemd hardening block

Final unit (relevant directives only; existing identity / Type / Restart blocks preserved):

```
[Service]
Type=notify
User=vault
Group=vault

ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
PrivateUsers=true
ProtectProc=invisible
ProcSubset=pid
ReadWritePaths=/var/lib/vault-daemon /run/vault-daemon
NoExecPaths=/var /home /tmp /root
UMask=0077

ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true
LockPersonality=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true

MemoryDenyWriteExecute=true
MemorySwapMax=0
MemoryMax=2G
TasksMax=64

NoNewPrivileges=true
CapabilityBoundingSet=CAP_IPC_LOCK
AmbientCapabilities=CAP_IPC_LOCK
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @reboot @swap @raw-io @cpu-emulation @keyring @clock @debug

RuntimeDirectory=vault-daemon
RuntimeDirectoryMode=0700
WatchdogSec=30
Restart=on-failure
LimitCORE=0
LimitNOFILE=4096
```

`systemd-analyze security vault-daemon` should report a score of 9.5 or better after this block.

### 6.5 S-10 / D-7 — `'unsafe-inline'` removal

**Where**: `vite.config.ts` Tailwind config, every component using inline `style={{...}}`, `web/server.js` CSP block.

**Approach**:

- Inline `style={{...}}` is allowed by CSP because React converts it to inline DOM attribute, not an inline `<style>` tag. The `'unsafe-inline'` is required only for `<style>` tags inserted by Tailwind's runtime injection.
- Tailwind v4 `@tailwindcss/vite` extracts all `@apply` and utility classes into a single content-addressed CSS file at build time. Only the `@layer base` reset injects at runtime.
- Solution: switch to CSS file output (no runtime JIT in production) by using `@tailwindcss/vite` build mode, ensuring the build artifact is a static `.css` referenced from `<link>`.
- After removal, CSP block becomes:

```
style-src 'self' 'sha256-<hash-of-tailwind-base-reset>'
```

with the SHA recorded at build time and injected into the Express CSP middleware.

### 6.6 C-06 / A.3 — LocalCryptoEnvelope v2

**Where**: `web/src/utils/localCrypto.ts`.

**Format**:

```
v1 (current): BASE64URL(headerJSON) . BASE64URL(iv concat ct) . BASE64URL(hmac)
              headerJSON = {"v":"1","alg":"A256GCM+HS256"}

v2 (new):     "lcv2." BASE64URL(header) "." BASE64URL(iv concat ct) "." BASE64URL(hmac)
              header (binary):
                byte 0      version = 0x02
                bytes 1..17 16-byte salt (Argon2id input)
                byte 17     log2(m) (12..18, 4 MiB..256 MiB)
                byte 18     t (1..6)
                byte 19     p (1..2)
                byte 20     reserved 0x00
```

- `K_master = Argon2id(localPassphrase concat sessionId, salt, m, t, p, 64 B)`.
- `K_aes  = HKDF-Expand(SHA3-512, K_master, "lcv2/aes",  32)`.
- `K_mac  = HKDF-Expand(SHA3-512, K_master, "lcv2/mac",  64)`.
- AAD on AES-GCM = `header concat keyName` (the localStorage key name) so an attacker cannot copy a ciphertext from `vault_credentials` into `vault_folders`.
- Read path tries v2 first (`startsWith("lcv2.")`), falls back to v1.

### 6.7 C-01 — Travel-mode KDF migration

**Where**: `web/src/utils/securityModes.ts::deriveTravelKeyBytes`.

- New `travel_mode_config.kdf_version: 1 | 2`.
- v2 calls `argon2idAsync` from `@noble/hashes/argon2` with `(m=64*1024, t=2, p=1, dkLen=32)`.
- Plain-HTTP fallback unchanged (PBKDF2 600 000 SHA-256).
- On unlock: try v2 first if version field present, else fall back to v1; on success, immediately re-encrypt the hidden vault under v2.

### 6.8 C-02 — Duress-mode hash storage

**Where**: `web/src/utils/securityModes.ts::armDuressMode, recordFailedLoginAttempt`.

- Replace SHA-256-based `timingSafeHash` with `argon2idAsync(passphrase, salt, m=64*1024, t=2, p=1, dkLen=32)`.
- Store the resulting 32 B as Base64 in a structure encrypted by the demo-mode local key (write via `writeEncryptedLocal`).
- Decrement counter mechanic unchanged. When the count reaches 0, fire the wipe.

### 6.9 G-1..G-7 — testing matrix

A canonical `tests/` directory under `web/` and `daemon/` will host:

- `daemon/tests/integration/protocol_strict.rs` — round-trips with extra fields rejected.
- `daemon/fuzz/fuzz_targets/parse_frame.rs` — `cargo-fuzz` target for msgpack parser.
- `web/src/utils/p2wAttack.test.ts` — already written; covers v1 vs v2 cracker.
- `web/src/utils/argon2_envelope.test.ts` — new; LocalCryptoEnvelope v2 round-trip plus v1 read compatibility.
- `web/src/utils/server_login.test.ts` — new; server-side MFA enforcement (mock fetch).
- `web/e2e/duress.spec.ts` and `forensic-wipe.spec.ts` — Playwright; full UI flows.

---

## 7. Verification matrix

| Finding | Verification command / step |
|---|---|
| D-01 | `cargo test --features pq-hybrid-1024 kem_roundtrip_v2`; sidecar dump shows `kem_suite=2` |
| D-03 | `journalctl -u vault-daemon` shows tuned params; manual benchmark `cargo bench argon2 -- --bench=tune` reports ~1 s |
| D-05 | `sqlcipher vault.db ".dbinfo"` displays correct cipher and `kdf_iter` |
| D-06 | `cargo test ipc_strict_unknown_field` |
| D-07 | strace shows BLKDISCARD ioctl during forensic wipe |
| S-01 | `curl -X POST /api/auth/login` plus skip 2FA returns 401 instead of session cookie |
| S-03 | `systemd-analyze security vault-daemon` reports `MemoryDenyWriteExecute=yes` |
| S-04 | `curl /api/system-info` post-setup returns 410 Gone |
| S-05 | New account login triggers Argon2id; legacy login triggers transparent rehash |
| S-06 | Six rapid `POST /api/auth/login` from one IP receive 429 |
| S-08 | `wscat -c wss://.../ws` rejects 5 MiB frame |
| S-10 | `curl -I /` shows `style-src 'self' 'sha256-...'` with no `'unsafe-inline'` |
| C-01 | Travel-mode unlock works on a v1 file and re-saves as v2 |
| C-02 | `localStorage.getItem('duress_mode_config')` shows ciphertext, no plaintext hash |
| C-06 | Round-trip test for `lcv2.` envelope; v1 still readable |
| X-01 | `cosign verify-blob` succeeds on release tarball |
| X-02 | `npm audit --audit-level=high` exits 0 in CI |

---

## 8. Migration strategy for existing users

1. **Vault DB**: at next unlock, daemon re-wraps the VMK under the hybrid 1024 suite and rewrites the sidecar. Audit log entry `KEM_SUITE_MIGRATED v1 -> v2`.
2. **Server accounts**: at next login, server verifies legacy scrypt then transparently rehashes the password with Argon2id and updates `users.enc`.
3. **`.p2w` files**: importer continues to read v1 indefinitely. Recommendation in the export UI: "your file was exported under suite 0x01; re-export to upgrade." Optional one-click "upgrade now" button.
4. **Local demo-mode storage**: the v1 to v2 LocalCryptoEnvelope is read-on-fallback; first write upgrades to v2.
5. **MFA storage**: the encrypted `mfa_config` blob is re-written under v2 envelope on next save.
6. **Travel-mode hidden vault**: re-encrypted to Argon2id on next successful unlock.

For users who decline migration (e.g., locked from updating), legacy code paths keep working until a sunset milestone announced in advance (default sunset: 12 months after L5 release).

---

## 9. Risks and open questions

- **R-1**: Argon2id m=1 GiB on a 4 GB Raspberry Pi unlocking a desktop-tuned vault — mitigated by sidecar-stored params that reflect the install host, plus a max-tolerance check that refuses to grind for >5 s on the unlocking host.
- **R-2**: ML-KEM-1024 ciphertext is 1568 bytes; sidecar size grows. Verify no path breaks at 8 KiB (some FS PRAGMAs).
- **R-3**: Removing `'unsafe-inline'` may regress a Tailwind plugin that injects via JS; need an end-to-end visual smoke test post-CSP-tightening.
- **R-4**: TLS hybrid X25519MLKEM1024 requires nginx with OpenSSL 3.4+; Ubuntu 24.04 LTS ships 3.0.x; need either a backport repo, BoringSSL, or operator guidance.
- **R-5**: SLSA Level 3 needs an isolated builder; for self-hosted CI this means a dedicated runner.
- **R-6**: Browser Argon2id via `@noble/hashes/argon2` is JS-only and slow at m=256 MiB; benchmark on mobile Safari before defaulting; consider WASM Argon2 (e.g., `argon2-browser`) for >64 MiB params.
- **R-7**: DOMPurify allowlist on SVG may be over-permissive for some attack-research SVG payloads; add fuzz coverage (Phase G-2).

---

## 10. `p2w-progress.md` format (for the integration prompt)

The companion progress file is a single-source-of-truth Markdown document that the integration agent always opens at the start of a turn and always updates at the end. The format is:

```
# PWDnow L99 integration — progress

> Last updated: <ISO8601 UTC>
> Status: in_progress | paused | blocked | done
> Active phase: A | B | C | D | E | F | G | H

## Phase status

| Phase | Items planned | Items done | Items skipped | Notes |
|---|---|---|---|---|
| A   | 7 | 0 | 0 | not started |
| ... | ... | ... | ... | ... |

## Per-item checklist

### Phase A — Symmetric crypto baseline lock-in
- [ ] A.1 Server scrypt -> Argon2id (S-05)
  - status: pending | in_progress | done | blocked
  - touched files: <list>
  - last commit: <sha or "uncommitted">
  - test command: npx vitest run web/src/utils/argon2_envelope.test.ts
  - blocker (if any): <text>
- [ ] A.2 Daemon Argon2id auto-tune (D-03)
  - ...

(... for every item ...)

## Open issues / decisions deferred

- ...

## Resume protocol

1. git status and git diff to see uncommitted work.
2. Read this file from top to bottom.
3. Pick the first item with status: in_progress and finish it.
4. If none in_progress, pick the first pending item under the active phase.
5. Update the item's status to in_progress before any edit.
6. After each finished item, update its status to done, set last commit, and git add plus commit (or note "uncommitted" if user has not asked for commits).
7. When the active phase has zero pending and zero in_progress items, move to the next phase and update Active phase.
```

The progress file is itself never committed silently; it is updated alongside any code edit so a reviewer can always answer "what changed and what is left" by reading just it.

---

## 11. Appendix — Document conventions

- All severities follow the calibration in section 4. CRIT findings block L5 claim; HIGH findings block L5 claim; MED and LOW are tracked but do not block.
- All file references use `path:line` form so a reviewer can jump directly.
- Sources of authority (in order, highest first):
  1. NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA).
  2. RFC 9106 (Argon2), RFC 5869 (HKDF), RFC 8439 (ChaCha20-Poly1305).
  3. OWASP Cheat Sheet — Password Storage (2024).
  4. systemd.exec(5) hardening directives (current Ubuntu LTS).
  5. Mozilla Observatory baseline plus CSP Level 3.

End of plan. The next prompt initiates integration; from that turn forward, all changes are tracked in `p2w-progress.md` so any interruption is recoverable without restarting.
