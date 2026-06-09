# PWDnow: Horizontal Scalability & CNSA 2.0 Architecture Plan

## 1. Executive Summary
This document outlines the architectural migration of PWDnow from a secure, single-node local appliance to a horizontally scalable distributed system. It strictly enforces a Zero-Knowledge architecture while adhering to **NIST Post-Quantum Cryptography (PQC) Level 5** and **CNSA 2.0 (Commercial National Security Algorithm Suite)** mandates.

## 2. Core Cryptographic Mandates (CNSA 2.0 Strict Mode)
To maintain compliance during horizontal scaling, all components across the distributed cluster must enforce the following cryptographic primitive suite. Legacy algorithms (e.g., X25519, Ed25519, ChaCha20) must be stripped from active communication paths.

*   **Symmetric Encryption:** AES-256-GCM.
*   **Key Establishment:** ML-KEM-1024 (FIPS 203).
*   **Digital Signatures:** ML-DSA-87 (FIPS 204).
*   **Hashing / PRF:** SHA-384 or SHA-512.
*   **Key Derivation:** PBKDF2-HMAC-SHA512 or HKDF-SHA384.

## 3. Scalability Bottlenecks & Architectural Solutions

> **Status legend:** ✅ done & verified · 🟡 partial / interim · ⬜ not started

### Phase 1: Decoupling IPC -> gRPC over PQC mTLS  — 🟡 **gRPC done, transport mTLS deferred**
**Current:** Unix Domain Socket (`/run/vault-daemon/vault.sock`) with `SO_PEERCRED`.
**Target:** Distributed gRPC interface.
*   **Implementation:** ✅ Replaced the Unix socket with a `tonic` gRPC server (`daemon/src/ipc/grpc_server.rs`, full `VaultService` — ~70 RPCs, wire schema in `proto/vault.proto`) and a `@grpc/grpc-js` client in the Node.js Web proxy (`web/server.js`, `POST /api/rpc` bridge). The browser `DaemonClient` (`web/src/utils/daemonClient.ts`) now POSTs to `/api/rpc` instead of using the WebSocket/msgpack path. The daemon binds `127.0.0.1:50051` (configurable via `--grpc-addr` / `DAEMON_GRPC_ADDR`).
*   **Authentication:** ✅ **Shared-secret peer-auth token** (interim, replaces `SO_PEERCRED`). Every RPC must carry an `x-daemon-token` metadata entry, enforced by a tonic interceptor (constant-time compare). The token comes from `DAEMON_GRPC_TOKEN` (env / K8s Secret) or a `0600` `grpc.token` file the daemon writes on first boot — so only a process running as the vault owner (able to read that file) can call the daemon, mirroring the old UID guarantee. The web proxy attaches the token on every call (`daemonMetadata()` in `server.js`).
*   **Security (transport mTLS):** 🟡 **Deferred — see feasibility note.** Transport is currently plaintext over loopback. This is acceptable for the single-node deployment (loopback is not network-observable by non-root, and a local attacker with loopback capture can already read process memory) but **must** be upgraded before any cross-node/distributed rollout.

> **⚠️ Feasibility note (ML-KEM-1024 in TLS):** The plan's literal mandate — "TLS 1.3 handshake MUST use ML-KEM-1024" with "ML-DSA-87 certificate signatures" — is **not achievable with the current Rust TLS ecosystem.** `rustls`/`tonic` expose no pure ML-KEM-1024 TLS key-exchange group; the only standardized PQC TLS group is the **X25519MLKEM768 hybrid** (RFC 9370 / draft-kwiatkowski-tls-ecdhe-mlkem), and `rustls` cannot parse ML-DSA-signed X.509 certs. Recommended path for the distributed phase: **hybrid mTLS** = X25519MLKEM768 KEM + classical (ECDSA P-384, CNSA-compatible) cert signatures, OR an app-layer ML-KEM-1024+AES-256-GCM envelope over classical mTLS (the daemon already carries the `ml-kem` crate). This deviation must be ratified before Phase 1 is closed.

### Phase 2: Local SQLite -> Distributed PostgreSQL (with ALE)  — ⬜ **not started**
**Current:** Local SQLite with SQLCipher full-database encryption.
**Target:** Highly Available PostgreSQL Cluster.
*   **Implementation:** Replace `rusqlite` with `sqlx` (Postgres async driver).
*   **Security (Application-Layer Encryption - ALE):** Because we lose SQLCipher's transparent local file encryption, the Vault Daemon must perform ALE. The daemon encrypts all structured vault payloads using AES-256-GCM (keyed by the user's VMK) *before* executing the SQL `INSERT`/`UPDATE` to PostgreSQL. 
*   **Zero-Knowledge DB:** The PostgreSQL database only ever stores ciphertexts. Even a full database compromise yields zero plaintext data.

### Phase 3: Stateful Sessions -> Distributed PQC Cache  — ⬜ **not started**
**Current:** In-memory session tracking and rate-limiting within a single Rust process.
**Target:** Distributed Redis Cluster.
*   **Implementation:** Deploy Redis for ephemeral state (MFA caches, lockout counters, session tokens).
*   **Security:** 
    1.  Connections from the Daemon to Redis must use PQC mTLS.
    2.  Data stored in Redis must be encrypted by the Daemon using a cluster-wide, rotating symmetric AES-256-GCM key (a Master Cache Key).

### Phase 4: Stateless Memory Protection  — ⬜ **not started** (depends on Phase 3)
**Current:** Vault Master Key (VMK) locked in local memory (`mlock`) per user session.
**Target:** Stateless, Ephemeral Key Management.
*   **Challenge:** If a user request hits Daemon Pod A, and the next request hits Daemon Pod B, Pod B does not have the `mlocked` VMK in its local RAM.
*   **Solution (The "Encrypted Session Box"):** 
    1.  When the user unlocks the vault, the VMK is derived. 
    2.  Instead of locking it permanently in RAM, the VMK is encrypted using an ephemeral "Session KEK" (derived from the user's short-lived session token).
    3.  This encrypted VMK payload is stored in Redis.
    4.  **Per-Request Flow:** When a request hits *any* Daemon Pod, the Pod fetches the encrypted VMK from Redis, decrypts it using the incoming Session Token, `mlocks` the VMK in RAM *only for the duration of the operation*, and immediately `zeroize`s the memory buffer when the gRPC call returns.
*   **Benefit:** Any Daemon node can securely handle any request, enabling massive Kubernetes Horizontal Pod Autoscaling (HPA) while preserving memory-zeroization guarantees.

## 4. Implementation Progress & Next Steps

### Done in this iteration (Phase 1)
*   ✅ `tonic` / `prost` / `tonic-prost(-build)` added to `daemon/Cargo.toml`; `build.rs` compiles `proto/vault.proto`.
*   ✅ `daemon/src/ipc/grpc_server.rs` — full `VaultService` implementation; `main.rs` now starts the gRPC server (Unix-socket `SocketListener` removed; dead `socket.rs` deleted).
*   ✅ Token-based peer authentication (tonic interceptor + `x-daemon-token` metadata) restoring the dropped `SO_PEERCRED` guarantee.
*   ✅ Web proxy: `@grpc/grpc-js` client + `POST /api/rpc` bridge + token attachment; `/health` now probes the daemon via gRPC `Ping` (was probing the removed Unix socket).
*   ✅ Deploy fixes required for the daemon to even start under hardening: `vault-daemon.service` (`RestrictAddressFamilies` now allows `AF_INET`/`AF_INET6`, `ExecStart` uses `--grpc-addr`, `EnvironmentFile` for the token, `StateDirectory`); AppArmor profile (allow loopback `inet`/`inet6 stream`, removed blanket `deny network`).
*   ✅ Verified: daemon builds (0 errors), `cargo test` 119 passing, web `tsc --noEmit` clean, web unit tests 161 passing, and an end-to-end gRPC smoke test confirms the token gate (valid → OK, wrong/missing → `UNAUTHENTICATED`) and a live `GetStatus` round-trip.

### Remaining for Phase 1 (before it can be marked ✅)
1.  **Transport mTLS** — implement hybrid PQC mTLS (X25519MLKEM768 + ECDSA-P384 certs) or an app-layer ML-KEM-1024 envelope; ratify the deviation from the literal ML-KEM-1024/ML-DSA-87 mandate (see feasibility note in Phase 1). Provision/rotate internal certs.
2.  **Cleanup** — remove the now-dead `Request` enum + frame codec in `daemon/src/ipc/protocol.rs` (kept `Response`, still used) and the dead `location /ws` block in `deploy/nginx/vault.conf`.
3.  **Multi-tenant identity** — the interceptor + handlers still assume a single UID (`auth_then!(… 1000 …)`); distributed/multi-user mode needs real per-request identity (cert CN or token-bound user id).

### Phases 2–4 (not started)
4.  **Storage Layer Rewrite (Phase 2):** Refactor `daemon/src/vault/` + `daemon/migrations/` to target PostgreSQL via `sqlx`, wrapping all reads/writes in an AES-256-GCM ALE layer (VMK-keyed). Zero-knowledge DB: ciphertext only.
5.  **State Management (Phase 3):** Add `redis` for ephemeral state (sessions, lockout counters, MFA caches) behind PQC mTLS, encrypted with a rotating Master Cache Key.
6.  **Stateless Memory (Phase 4):** "Encrypted Session Box" — VMK wrapped by a session-token-derived KEK, stored in Redis, fetched + `mlock`ed + `zeroize`d per request so any pod can serve any request (K8s HPA).
