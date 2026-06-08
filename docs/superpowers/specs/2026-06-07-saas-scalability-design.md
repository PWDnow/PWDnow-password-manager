# PWDnow — SaaS Scalability Design (Model C: Two-Track)

**Date:** 2026-06-07
**Status:** Approved design — ready for implementation planning
**Scope decisions (locked):**
- **Scaling model:** C — Two-track. The Rust daemon stays single-tenant for the self-host/local product and is **out of scope, unchanged**. The web "server-mode" (Express) path becomes the scalable multi-tenant SaaS.
- **Scale target:** 10k–100k+ users, Kubernetes HPA.
- **Deployment:** Both / phased — single-node correctness now, every component designed cluster-ready, incremental K8s move.
- **SaaS key model:** Per-user envelope encryption with KMS-wrapped DEKs.

> **Non-goal / invariant:** CNSA 2.0 / NIST PQC L5 crypto posture is preserved everywhere. No primitive is weakened. The daemon (Layer 1) is **not** modified by this work.

---

## 1. Background — why this work exists

PWDnow currently embodies two architectures that do not share storage, identity, or state models:

- **(A) Single-tenant local appliance** — the Rust daemon (`daemon/`). `DaemonState` (`daemon/src/vault/state.rs:110-131`) holds exactly one VMK, one DB connection, one `vault_uuid`; every gRPC handler hardcodes `uid = 1000` (`daemon/src/ipc/grpc_server.rs`, 17 sites). One process = one unlocked vault. True zero-knowledge, L5.
- **(B) Multi-tenant file-backed web service** — Express "server-mode". Per-user `.enc` files under `auth_data/vault/<uid>/` coordinated by `proper-lockfile`; one global `users.enc`; one installation key (`auth_data/.master_key`) derives all per-file keys via HKDF (`web/lib/fileCrypto.js:17-25`).

Multiple users flow through (B) today (24 vault dirs in `auth_data/`). This design scales **(B)** while leaving **(A)** as the self-host product.

### Confirmed bottlenecks in the SaaS (server-mode) path
- **B3 — File-store doesn't cluster.** Per-user `.enc` files + `proper-lockfile` only work on a single host with a local FS (`web/lib/fileCrypto.js`, `web/lib/session.js:154`).
- **B4 — Per-process in-memory state.** Rate limiters, account/fingerprint lockouts, OTP/challenge stores, session JTI tracking are in-process Maps (`web/lib/rateLimiter.js`). Rate-limit and lockout are **bypassable by hitting another worker/node**; the sessions cache is deliberately disabled (`web/lib/session.js:95-99`, `TTL=0`) for PM2 correctness, forcing a full file decrypt on every auth check.
- **B7 — `users.enc` global lock + write amplification.** Every user mutation rewrites the whole encrypted file under a global lockfile (`withUsersLock`, `web/lib/fileCrypto.js:137`); `loadUsers()` decrypts the entire file on every call with no cache (`web/lib/fileCrypto.js:103-107`).
- **B6 — Login throughput ceiling.** Argon2id 128 MiB × t=3 gated to `ARGON2_MAX_CONCURRENT = 3` (`web/lib/rateLimiter.js:7-13`), ~6–8 s each. Correct for AAL3; must be scaled horizontally, never weakened.
- **Key liability at scale.** A single installation key (`auth_data/.master_key`) decrypting all vaults is unacceptable at 100k users across stateless pods.

### What is already right (do not rewrite)
- Crypto core (ML-KEM-1024 / ML-DSA-87 / AES-256-GCM / Argon2id) — L5 / CNSA 2.0.
- Application-Layer Encryption is already the model in server-mode (ciphertext blobs), so a Postgres backend stores ciphertext with near-zero crypto change.
- Atomic writes (tmp+fsync+rename), HMAC blind-index on email, audit HMAC hash-chain — all port cleanly to a real DB.

---

## 2. Target architecture

### 2.1 Two-track topology
- **Self-host track (unchanged):** browser → Express → daemon (gRPC) → SQLCipher. Single-tenant, true zero-knowledge, L5.
- **SaaS track (new):** browser → **stateless Express pods** → **Postgres** (durable ciphertext) + **Redis** (ephemeral state) + **KMS** (key wrapping). No daemon in this path; Express performs per-user envelope ALE.

The two tracks are selected at deploy time / per-installation configuration. Server-mode code paths are refactored behind storage/state interfaces so the file-store remains the self-host default and Postgres/Redis become the SaaS implementation.

### 2.2 Key hierarchy — per-user envelope + KMS
```
KMS CMK  (never leaves KMS / HSM)
  └─ wraps per-user DEK (AES-256)  → stored as `wrapped_dek` in users table
        └─ DEK decrypts that user's vault item blobs (AES-256-GCM ALE)
```
- **Per request:** load `wrapped_dek` from Postgres → KMS-decrypt to obtain the DEK in memory → en/decrypt the user's items → zeroize the DEK buffer.
- **KMS QPS control:** a short-TTL (~60 s) in-process DEK LRU keyed by `user_id` bounds KMS calls at scale. (Cached DEKs live only in pod memory, never persisted to Redis in plaintext.)
- **Blast radius:** compromise of one user's row + its KMS grant cannot unwrap any other user's DEK. Replaces the single global `auth_data/.master_key` for the SaaS path.
- **Open option (decide in P1):** additionally wrap the DEK with a password-derived (Argon2id) key so that even a combined KMS+DB compromise still requires the user password. Trade-off: complicates server-side password reset / recovery. Default for MVP: KMS-wrapped DEK only (server-recoverable); password-bound wrap is a later opt-in "enhanced" tier.

### 2.3 Postgres schema (replaces the flat `.enc` file-store)
- `users(id uuid pk, email_hmac text unique, password_hash text, wrapped_dek bytea, kms_key_id text, status text, created_at timestamptz)` — keep the HMAC-SHA256 blind index on email (`hashEmail`, `web/lib/fileCrypto.js:118-122`).
- `vault_items(id uuid pk, user_id uuid fk, type text, ciphertext bytea, nonce bytea, aad bytea, version int, updated_at timestamptz)` — **one row per item**; eliminates `users.enc`/per-resource-file rewrite amplification (B3/B7). `type ∈ {credential, folder, asset, profile, mfa}`.
- `sessions(jti text pk, user_id uuid fk, expires_at timestamptz, device text, ip_hash text, revoked bool)` — enables cross-node revocation (replaces `sessions.enc`).
- `audit_log(...)` — append-only, HMAC hash-chained (port existing chain).
- **Driver:** `pg` (node-postgres) with a connection pool + a thin parameterized query module (no heavy ORM — matches the lightweight `web/lib/` style). Parameterized queries only.
- **Migrations:** SQL files via `node-pg-migrate`.

### 2.4 Distributed state — Redis behind a `StateStore` interface
A `StateStore` abstraction with two implementations: **in-memory** (self-host / single-node default) and **Redis** (SaaS, cluster-mode ready). Migrated state:
- Rate limiters + account/fingerprint lockouts → Redis `INCR` + `EXPIRE` (atomic, cluster-correct). **Fixes B4 bypass.**
- Session JTI checks → Postgres source-of-truth + Redis cache with pub/sub invalidation on logout / password-change → re-enables the cache disabled at `web/lib/session.js:95` without the PM2 correctness bug.
- Email OTP / challenges → Redis with TTL + single-use (Lua compare-and-set).
- **Cluster-wide Argon2 admission control** → Redis token bucket capping concurrent hashes across the whole cluster (extends `ARGON2_MAX_CONCURRENT`, B6), returning fast backpressure ("server busy, retry") instead of unbounded queueing.

### 2.5 Stateless pods + secrets (Kubernetes)
- Express → K8s Deployment + **HPA** (CPU + custom metric: login-queue depth). Optional dedicated **auth-worker pool** sized for CPU so 6–8 s Argon2 hashes don't starve vault-read pods.
- Secrets: KMS CMK (cloud KMS or HashiCorp Vault), DB creds, JWE session secret → K8s Secrets / Vault. The JWE session key (currently HKDF from the local master key, `web/lib/session.js:28`) becomes a dedicated managed secret with a **key-id header** for zero-downtime rotation.
- Data-in-transit: TLS 1.3 to Postgres/Redis. Managed services rarely support PQC TLS today → **ALE is the zero-knowledge-at-rest guarantee**; the classical-TLS residual is documented and accepted (data is ciphertext before it leaves the pod).

### 2.6 Login throughput (B6) at scale
Argon2id stays at AAL3 params. Capacity = more pods + the Redis admission bucket from §2.4. Fast backpressure response under saturation; never weaken KDF parameters.

---

## 3. Phased rollout

### P0 — Single-node, cluster-ready (no behavior change for self-host)
- Introduce `StateStore` and `VaultRepository` interfaces.
- Wire optional Redis (falls back to in-memory `StateStore`).
- Fix the rate-limit / lockout cross-worker bypass bugs via the new `StateStore`.

### P1 — Postgres + envelope/KMS
- Postgres schema + `VaultRepository` Postgres implementation.
- Per-user DEK + KMS wrapping introduced here.
- Dual-write (file + Postgres), then a backfill migrator: read `auth_data/`, re-encrypt each user under a fresh per-user DEK, insert.
- Flag-gated read cutover to Postgres.

### P2 — Redis everywhere
- All ephemeral state on Redis.
- Re-enable session cache with pub/sub invalidation.

### P3 — Kubernetes
- Containerize; manifests; HPA; KMS/Vault secrets; TLS to data stores.
- k6 load-test to the 100k target; tune pool sizes, DEK LRU TTL, Argon2 bucket.

---

## 4. Verification strategy
- **Contract tests:** a single suite that both `VaultRepository` implementations (file + Postgres) and both `StateStore` implementations (in-memory + Redis) must pass.
- **Load tests:** k6 per phase against the scale target.
- **Regression gate:** keep `web/e2e/comprehensive-platform.spec.ts` green throughout, in **both** modes.
- **Metrics:** request latency, KMS QPS, DEK cache hit-rate, login-queue depth, Argon2 concurrency, Postgres pool saturation, Redis op latency.

---

## 5. Open decisions to confirm at planning time
1. **Cloud / KMS target:** AWS KMS · GCP KMS · HashiCorp Vault Transit. (Drives the KMS adapter and IAM model.)
2. **Password-bound DEK wrap (§2.2):** include in P1 or defer to an enhanced tier.
3. **Managed vs self-run Postgres/Redis** (affects TLS/PQC posture and HA topology).

---

## 6. Out of scope
- The Rust daemon (`daemon/`) and the self-host/daemon-mode browser path.
- Any change to CNSA 2.0 / L5 cryptographic primitives.
- The daemon's gRPC mTLS work (tracked separately in `docs/superpowers/plans/horizontal-scalability-cnsa2.md`).
