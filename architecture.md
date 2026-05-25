# PWDnow Architectural Overview & Technical Reference

PWDnow is a highly secure, local-first, two-layer password management system designed to meet NIST Security Level 5 and CNSA 2.0 (Commercial National Security Algorithm Suite) requirements. The platform strictly enforces a Zero-Knowledge architecture, ensuring that the web-based frontend never handles plaintext key material. 

This document details the complete system architecture, encompassing the Rust cryptographic daemon, the React frontend, the inter-process communication protocol, and the proprietary P2W encrypted file storage format.

---

## 1. High-Level Architecture: The Two-Layer Model

The system separates the user interface from cryptographic operations via a strict process boundary. 

### Layer 1: Vault Daemon (`daemon/`)
The daemon is a standalone Rust process providing the cryptographic engine, persistent storage, and secure memory operations. 
*   **Operating Modes**: Runs fully offline, strictly bound to the local machine.
*   **Storage Backend**: Uses SQLite with the SQLCipher extension for encrypted persistence.
*   **Memory Protection**: Employs OS-level memory locking. The Vault Master Key (VMK) is stored within a `LockedKey` struct, utilizing `mlock()` to prevent the key from being paged to disk. During idle periods, the memory pages are sealed using `mprotect(PROT_NONE)`, preventing any access (even from within the daemon process) until explicitly unlocked for an operation. 
*   **Zeroization**: The `zeroize` crate guarantees that sensitive buffers are wiped from memory immediately after use or when they fall out of scope.
*   **Cryptography**: Uses advanced primitives including AES-256-GCM, Argon2id for Key Derivation, and Post-Quantum cryptography (ML-KEM-768/1024 hybrid KEMs and ML-DSA-87 signatures) via feature flags (e.g., `--features pq`, `--features cnsa-strict`).
*   **Monitoring**: A companion daemon, `pwdnow-monitor`, continuously checks system health, including RAM leaks (SLA P1), disk space, CPU utilization, and systemd watchdog heartbeats.

### Layer 2: Web Interface (`web/`)
The frontend is a React 19 Single Page Application (SPA), utilizing TypeScript, Vite, React Router v7, and Tailwind CSS v4.
*   **Zero-Knowledge UI**: The frontend never sees the Master Key, KEK (Key Encryption Key), VMK, or DEK (Data Encryption Key). All sensitive inputs are passed to the daemon, which returns opaque encrypted blobs or success/failure flags.
*   **Session Management**: Authentication state is maintained via a fast-expiring `session_token`. The token is stored purely in memory using a JavaScript private class field (`SecureKeyStore`) and is aggressively cleared on visibility changes (`pagehide`, `visibilitychange -> hidden`), logouts, and tab closures. 
*   **Server Component**: An Express.js backend (`web/server.js`) serves the static assets, enforces strict Content Security Policies (CSP) with per-request nonces, and acts exclusively as a WebSocket proxy to forward Layer 2 requests to Layer 1.

---

## 2. Inter-Process Communication (IPC) Protocol

Communication between the Web Proxy and the Vault Daemon flows over a Unix Domain Socket (`/run/vault-daemon/vault.sock`). 

### Protocol Design
*   **Transport**: MessagePack binary framing over Unix Sockets.
*   **Authentication**: The daemon aggressively verifies the connecting client using OS-level `SO_PEERCRED` checks to ensure the connection originates from the trusted proxy service (the `vault` user/group), mitigating privilege escalation and cross-user snooping.
*   **Command Dispatch**: Every message uses a strongly-typed Request/Response enum (`daemon/src/ipc/protocol.rs`). The web client (`web/src/utils/daemonClient.ts`) wraps these calls in a `DaemonClient` abstraction that serializes arguments into MessagePack payloads.
*   **Session Validation**: After the initial `Unlock` operation, all subsequent authenticated IPC calls must supply the `session_token`. The daemon validates this token using an `auth_then!` macro before processing the request.

---

## 3. Cryptographic Hierarchies & Data Persistence

PWDnow employs a tiered cryptographic key hierarchy.

### Key Derivation
The Vault Master Key (VMK) encrypts the underlying SQLCipher database. The VMK itself is derived or unlocked using the user's master password. The daemon handles the KDF (Argon2id) logic, ensuring high memory/CPU cost to deter offline brute-force attacks.

### SQLCipher Storage
*   The primary vault data is stored in a SQLite database encrypted via SQLCipher 4 (`/var/lib/vault-daemon/vault.db`). 
*   To maintain stability under load, the daemon implements Write-Ahead Logging (WAL) and automated checkpointing.

---

## 4. The P2W Format (Proprietary Vault Export)

P2W is PWDnow's proprietary export format, heavily optimized for security against offline tampering, decryption, and traffic analysis. The format uses a strict TLV (Tag-Length-Value) encoded sequence of records, preceded by a DOS-style "nz" (0x6E 0x7A) stub.

### P2W Cipher Suites

The system supports two suites. Suite 0x01 is legacy and import-only. Suite 0x02 is the current default for all operations.

#### Suite 0x02 (Current Default)
*   **KDF**: Argon2id (RFC 9106).
    *   Parameters: `m = 256 MiB` (log2=18), `t = 3` (or `t = 1` for exports), `p = 1`.
*   **Key Derivation**: Subkeys are derived from the master secret using HKDF-SHA3-512 with domain-separation labels (e.g., `p2w/v2/aes-256-gcm`).
*   **Encryption**: Double AEAD (Authenticated Encryption with Associated Data).
    *   Inner Layer: `AES-256-GCM`
    *   Outer Layer: `XChaCha20-Poly1305`
    *   *AAD Binding*: The 96-byte plaintext header is bound into both AEAD tags as Associated Data to prevent header manipulation.
*   **Authentication**: `HMAC-SHA3-512` applied twice (once over the header, once over the entire file).

### Privacy & Anti-Fingerprinting (P2W Format Enhancements)
1.  **Exponential Padding (F-02)**: To mask the exact number of credentials and their lengths, random padding records (`R_PADDING = 0xFE`) are appended to the payload. Padding targets exponential buckets (64 KB, 256 KB, 1 MB, then 1 MB boundaries) to defeat size-based heuristics.
2.  **Metadata Obfuscation (F-07)**: In Suite 0x02, the plaintext header zeroes out the `CREATED`, `CRED_COUNT`, and `FOLD_COUNT` fields. This information is only accessible after decrypting the PRF payload.
3.  **Strict State Machine (F-03/F-16)**: The P2W parser enforces a strict sequence of records (`META` -> `FOLDERS` -> `ENTRIES` -> `PADDING` -> `END`). Out-of-order records or unknown tags instantly abort the process, preventing maliciously crafted files from forcing the parser into an unexpected state.

---

## 5. Security & Authentication Mechanisms

### Multi-Factor Authentication (MFA)
PWDnow supports a full spectrum of MFA options, managed in memory and synced securely with the daemon.
*   **WebAuthn / FIDO2**: Full support for cross-platform hardware keys (YubiKey) and platform authenticators (Touch ID, Windows Hello).
*   **TOTP / HOTP**: RFC 6238 compliant generation.
*   **MFA Configuration Storage**: The MFA configuration (`MfaConfig`) is cached in memory (`_mfaCache`), synchronized to the daemon, and optionally persisted to `localStorage` encrypted using an AES-GCM signed token. TOTP secrets are never exposed in plaintext.

### Session Lifecycles
*   **Lockout Counters**: The daemon tracks failed login attempts and implements exponential backoff to prevent brute forcing.
*   **Forensic Wipe**: A specialized capability token (`WIPE_TICKET_KEY`) is issued on unlock. In an emergency, sending a `ForensicWipe` command with this ticket causes the daemon to overwrite the vault files with 7 passes and exit immediately.

### Threat Mitigation
*   **DOM Injection**: React's strict rendering handles most XSS. However, user-provided SVGs (e.g., custom folder icons) are strictly sanitized via DOMPurify to prevent script execution.
*   **Replay Attacks (MFA)**: TOTP verification incorporates a used-token memory cache to reject codes that have already been consumed within the current period.
*   **Memory Leaks**: The `pwdnow-monitor` incorporates an SLA P1 leak detector that polls the RSS of the Web and Daemon processes, triggering CRITICAL alerts (and auto-restarting PM2/daemon) if monotonic RAM growth is observed.

---

## Summary
The PWDnow architecture is fundamentally designed around the assumption of a hostile environment. By confining all cryptographic execution to a memory-protected, memory-zeroizing Rust daemon, and utilizing a stateless, zero-knowledge presentation layer, PWDnow isolates key material from the vulnerabilities inherent to browser environments. The P2W format extends this philosophy to data at rest, utilizing state-of-the-art Double-AEAD encryption, post-quantum readiness, and rigorous privacy paddings to guarantee absolute data sovereignty.
