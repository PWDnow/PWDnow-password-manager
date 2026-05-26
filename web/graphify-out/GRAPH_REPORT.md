# PWDnow — GRAPH_REPORT.md
> Auto-generated knowledge graph analysis of the PWDnow codebase (59 nodes · 70 edges · 4 communities)

---

## 🏛 Architecture Overview

PWDnow is a **two-layer, zero-knowledge password manager**:

| Layer | Technology | Location |
|-------|-----------|----------|
| **Vault Daemon** | Rust + Tokio + SQLCipher | `daemon/` |
| **Web Frontend** | React 19 + TypeScript + Vite | `web/` |
| **Monitor** | Rust + Tokio (watchdog) | `monitor/` |
| **IPC Bridge** | WebSocket → Unix Socket → msgpack | `web/server.js` |

---

## 🔑 Key Concepts

### 1. God Nodes (Highest Fan-Out)
| Node | Edges | Why It Matters |
|------|-------|----------------|
| `DaemonState` | 19 out | Central nervous system — holds VMK, DB, sessions, lockout, all vault ops |
| `daemonClient.ts` | 12 out | Single WebSocket channel for all 40+ IPC commands from the browser |
| `socket.rs` | 5 | IPC gateway — deserializes msgpack, dispatches to DaemonState |
| `main.tsx` | 5 | React root — mounts all contexts and router |
| `db.rs` | 4 | SQLCipher connection factory, migration chain v0→v4 |

### 2. Cryptographic Hierarchy
```
Master Password
    │
    ├─ Argon2id (256 MiB, t=3, p=4) → KEK[0..32]
    │    └─ AES-256-GCM decrypt → VMK (32 bytes, mlock'd)
    │         ├─ HKDF-SHA3-512("vault-sqlcipher-key-v2") → SQLCipher key
    │         ├─ HKDF-SHA3-512("vault-blind-index-key-v1") → Blind-index key
    │         ├─ Per-credential random DEK (AES-256-GCM) → encrypted blob
    │         └─ HKDF-SHA-384("sidecar-hmac") → Header HMAC key
    │
    └─ Browser-side (never sees VMK)
         ├─ PBKDF2-SHA-512 (600K iters) → v1 local AES-GCM key
         └─ Argon2id (128 MiB, t=3) + HKDF-SHA-384 → v2 local AES-GCM key
```

### 3. Session Security Model
- **15-min idle TTL** + **24-hour absolute TTL** (non-extendable)
- **8 sessions per user**, **1000 global cap**
- Token = 32 random bytes, hex-encoded, held in JS private class field
- `SO_PEERCRED` UID binding — WebSocket proxy UID must match session UID
- Revoked token BLAKE3 hashes kept for replay prevention within absolute-TTL window

### 4. IPC Protocol
- **Transport**: Unix Domain Socket at `/run/vault-daemon/vault.sock`
- **Wire format**: msgpack with `deny_unknown_fields` (prevents injection attacks)
- **Frame**: 4-byte big-endian length prefix + msgpack body (max 4 MiB)
- **Auth**: every authenticated command carries `session_token`; validated by `auth_then!` macro
- **40+ commands** across 7 categories: Auth, Folders, Credentials, FIDO2/Passkey, TOTP, HIBP, Audit

---

## 🌐 Community Analysis

### Community 1: Vault Daemon (Rust) — 23 nodes
**Hub**: `DaemonState` (state.rs, 1419 lines)  
**Critical path**: `main.rs → SocketListener → DaemonState → kdf.rs → db.rs → credentials.rs`  
**Unique features**:
- FIPS 140-3 power-on self-tests before socket bind
- Adaptive Argon2id tuning (`kdf_tune.rs`) targeting ~1s on current HW
- Dispatch-driven watchdog (dead-lock safe vs timer-driven)
- WAL checkpoint every 30s to cap crash recovery time
- `mlock()`'d memory via `LockedKey` + `zeroize` on drop

### Community 2: Web Frontend (React/TS) — 28 nodes
**Hub**: `daemonClient.ts` (26 KB, 659 lines)  
**Critical path**: `Login.tsx → keystore.ts → daemonClient.ts → server.js → vault.sock`  
**Unique features**:
- Phase A/B/C parallel key derivation in Login.tsx (PBKDF2 concurrent with Argon2id)
- Argon2id runs in dedicated Web Worker to avoid UI jank
- `SecureKeyStore` — session token in JS `#private` field, never in React state
- Trusted Types policy backed by DOMPurify for XSS prevention
- P2W proprietary encrypted export format with size-obfuscating padding

### Community 3: Monitor Daemon (Rust) — 6 nodes
**Hub**: `main.rs` poll loop  
**Critical path**: `SystemCollector → RiskEngine → ActionEngine → restart service`  
**Unique features**:
- 36-sample sliding window for monotonic RAM growth detection
- SIGHUP hot-reload for thresholds/healing/notify config
- Per-day TLS cert expiry check with 14/5/0-day alert thresholds
- Targets **99.99% SLA** via predictive auto-healing

### Community 4: Infrastructure — 1 node
`deploy/Makefile`: orchestrates `cargo build --release` + `npm run build`, with optional `--features pq` for ML-KEM-768 post-quantum hybrid KEM.

---

## ⚡ Surprising Connections

1. **`p2wFormat.ts` ↔ `localCrypto.ts`**: The proprietary P2W format uses the same AES-256-GCM primitives as the local credential cache — meaning a compromised local key could theoretically decrypt both the cache AND exported P2W files.

2. **`vault/state.rs` owns `wipe.rs`**: The forensic wipe (7-pass DoD overwrite) is triggered by `DaemonState.forensic_wipe_internal()`, which can be called either via an explicit `ForensicWipe` IPC command OR automatically when the `duress_max_attempts` lockout threshold is reached — creating a silent self-destruct on brute force.

3. **`session.rs` uses BLAKE3 for revocation** (not the session token algorithm): The session token itself is 32 random bytes (hex), but the revocation blacklist stores BLAKE3 hashes of tokens — so even if the revoked token store is exfiltrated, the original tokens cannot be recovered.

4. **`monitor/action.rs` can restart both the daemon AND the web server**: The monitor has auto-healing privileges over both layers, creating a potential privilege escalation surface if the monitor config is writable by an attacker.

5. **`Login.tsx` runs 3 parallel KDF phases**: Phase A (PBKDF2-SHA-512) starts immediately on password entry, Phase B (daemon Argon2id) starts concurrently, Phase C (browser Argon2id) begins after the daemon token is returned. This hides the KDF latency inside each other.

---

## 🗄 Database Schema (SQLCipher v4)

| Table | Purpose | Encryption |
|-------|---------|-----------|
| `vault_meta` | Schema version, migration flags | Plaintext in encrypted DB |
| `users` | Profile: name, email, pic (encrypted), password_changed_at | VMK-encrypted blobs |
| `folders` | Encrypted folder rows with blind index | AES-256-GCM per-row |
| `credentials` | Encrypted credential blobs + DEKs + blind index | Per-row DEK wrapped by VMK |
| `asset_holder` | Single encrypted JSON blob (emails/phones/U2F) | VMK-encrypted |
| `audit_log` | Append-only tamper-evident log with BLAKE3 chain | VMK-encrypted per entry |
| `fido2_credentials` | Hardware key metadata | Plaintext IDs, VMK-encrypted blobs |
| `otp_config` | TOTP secrets + backup codes (Argon2id hashed) | VMK-encrypted |
| `pqc_credentials` | ML-DSA-87 verifying keys, ML-KEM-1024 seeds | VMK-encrypted |

**Schema migrations**: v0→v1 (initial), v1→v2 (defense-in-depth: blind indexes, new encryption), v2→v3 (PQC auth tables), v3→v4 (FK fix for credentials table after folder rename)

---

## ❓ Suggested Questions to Explore

1. **"How does the passkey VMK wrap key get derived from auth_data?"**  
   → Trace: `fido2.rs::derive_vmk_wrap_key()` → `auth_data` bytes → HKDF → wrap key → XChaCha20 decrypt VMK copy

2. **"What happens when the duress password is entered?"**  
   → `LockoutTracker.record_failed_unlock()` → check `duress_max_attempts` → `forensic_wipe_internal()` → 7-pass overwrite → process exit

3. **"How does a credential get stored end-to-end?"**  
   → Browser: `Vault.tsx` → `daemonClient.addCredential()` → msgpack → WebSocket → `server.js` proxy → Unix socket → `socket.rs::dispatch()` → `DaemonState::add_credential()` → random DEK → AES-256-GCM encrypt blob → store `(encrypted_dek, ciphertext)` in SQLCipher

4. **"Why does Login.tsx have three phases?"**  
   → To parallelise the browser-side PBKDF2 (Phase A) with the daemon's Argon2id (Phase B) so total login time = max(PBKDF2, Argon2id) not sum. Phase C derives the v2 Argon2id browser key using the session token as binding context.

5. **"How is the audit log tamper-evident?"**  
   → Each entry includes `prev_hash` (BLAKE3 of previous entry). `audit::verify_chain()` walks all entries on unlock, recomputes hashes, and returns `Err` if any link is broken — indicating database tampering.

6. **"What makes the monitor's watchdog dead-lock safe?"**  
   → Unlike a free-running timer, the watchdog only sends `WATCHDOG=1` if `in_flight_requests == 0` OR a request completed within `stall_secs`. A deadlocked dispatcher keeps `in_flight > 0` with no completions → watchdog skips heartbeat → systemd restarts.

---

## 📁 File Reference

| File | Lines | Role |
|------|-------|------|
| `daemon/src/vault/state.rs` | 1419 | Master state machine — god file |
| `daemon/src/ipc/socket.rs` | ~900 | IPC dispatch — all 40+ commands |
| `daemon/src/ipc/protocol.rs` | 625 | Wire protocol enum definitions |
| `web/src/utils/daemonClient.ts` | 659 | TypeScript IPC client |
| `web/src/pages/Login.tsx` | ~900 | Login UI + 3-phase KDF |
| `web/src/pages/Vault.tsx` | ~900 | Main credential UI |
| `web/src/utils/importExport.ts` | ~800 | Multi-format import/export |
| `web/src/utils/mfa.ts` | ~700 | WebAuthn flows |
| `web/src/crypto/keystore.ts` | 478 | Key derivation + secure storage |
| `web/src/utils/p2wFormat.ts` | ~600 | Proprietary P2W format |

---

*Generated by graphify analysis · PWDnow v1.0.0 · 2026-05-26*
