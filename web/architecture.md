# Secure Password Manager : Architecture Design

---

## 1. Threat Model

**Assets to protect:**
- Master credentials (plaintext passwords, OTP secrets, KBA answers)
- Vault keys in memory (KEK, VMK, DEKs)
- Authentication credentials at rest and in transit
- Local SQLite vault file (stolen device / stolen disk)
- User identity (email, name, profile picture)

**Adversary classes:**
- Stolen device / stolen SQLite file : offline brute force against the encrypted vault
- Server/database compromise : zero-knowledge must hold for sync server
- Network interception : TLS + AEAD mitigates
- Compromised client process : memory scraping, ptrace
- Brute force / credential stuffing against sync API
- Quantum adversary : harvest-now-decrypt-later threat
- Malicious insider : audit logs, key separation
- Physical access : YubiKey is hardware root; disk encryption (LUKS2) as secondary layer

**Non-goals (out of scope for this layer):**
- OS-level rootkits on the client
- Nation-state targeted keyloggers
- Physical shoulder surfing

---

## 2. Two-Layer Architecture

The system has two distinct layers that combine into a unified product:

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 2: Optional Web / GUI Frontend  (React 19 + TypeScript)│
│  Communicates with Layer 1 via Unix socket (localhost only)  │
└──────────────────────┬───────────────────────────────────────┘
                       │ Unix socket (AF_UNIX, peercred auth)
┌──────────────────────▼───────────────────────────────────────┐
│  Layer 1: Vault Daemon  (Rust, static-linked)                │
│  libsodium · libfido2 · sqlcipher · liboqs                   │
│  Local-first, offline-capable, YubiKey-bound                 │
│  SQLite + SQLCipher vault file (AES-256-GCM, page-level)     │
└──────────────────────────────────────────────────────────────┘
                       │ Optional encrypted sync only
┌──────────────────────▼───────────────────────────────────────┐
│  Layer 3: Optional Sync  (Cloudflare Zero Trust tunnel)      │
│  Transfers encrypted SQLite file between trusted devices     │
│  Never decrypts vault data, never handles authentication     │
└──────────────────────────────────────────────────────────────┘
```

**Foundational principle**: No mandatory network dependency. The vault daemon runs fully offline. Sync is opt-in and transfers only the already-encrypted SQLite file : the sync server never sees plaintext.

---

## 3. Zero-Knowledge Principle

The sync server (if used) **never** sees:
- The master password or YubiKey response
- Any plaintext vault contents
- The vault encryption key in any form

All encryption/decryption happens inside the vault daemon process, in mlock()ed memory, on the local device.

For the optional multi-user web deployment (self-hosted), OPAQUE protocol (IRTF RFC draft, augmented PAKE) is used:
- Client authenticates without transmitting a hash or password
- Server stores an OPAQUE record, not reversible to password
- OPAQUE exports a deterministic key that becomes master key material

---

## 4. Cryptographic Architecture

### Key Hierarchy

```
[Local / Offline Mode]

Master Password  +  YubiKey HMAC-SHA256 response (slot 2, 32-byte challenge)
        │
        ▼
  Argon2id  (m=256MB, t=3, p=4)           ← NIST SP 800-132 / RFC 9106
        │
        ▼
  512-bit Master Key Material
   ├── [0..255]   KEK  (Key Encryption Key)
   └── [256..511] Auth Key  (for optional server OPAQUE handshake only)

  Vault Master Key (VMK)  ← 256-bit random, generated once at vault creation
        │
        ▼
  XChaCha20-Poly1305(KEK, VMK)  → encrypted_vmk  → stored in SQLite

  Per-Credential DEK  ← 256-bit random per credential
        │
        ▼
  XChaCha20-Poly1305(VMK, DEK)  → encrypted_dek  → stored with credential
        │
        ▼
  XChaCha20-Poly1305(DEK, plaintext_blob)  → ciphertext  → stored in SQLite
```

**YubiKey binding**: The HMAC-SHA256 challenge-response (slot 2) is a mandatory component of KEK derivation in local mode. Without the physical YubiKey, Argon2id receives only the master password : KEK is different and the vault cannot be opened. The 32-byte challenge is derived deterministically from the vault UUID so it is reproducible across unlocks without network access.

**Why dual-layer DEKs**: VMK compromise only requires re-encrypting the VMK, not every credential. Individual credentials can be re-keyed independently. VMK rotation is a single atomic operation.

### Authenticated Encryption

| Use case | Algorithm | Notes |
|---|---|---|
| Vault page encryption | AES-256-GCM (SQLCipher) | Page-level, hardware AES-NI |
| VMK at rest | XChaCha20-Poly1305 | 192-bit nonce, libsodium |
| DEK at rest | XChaCha20-Poly1305 | 192-bit nonce |
| Credential blobs | XChaCha20-Poly1305 | AAD = vault_id\|\|cred_id\|\|version |
| OTP secrets, recovery codes | AES-256-GCM inner layer | Double-encrypted for classified fields |
| Backup VMK copy (FIDO2 passwordless) | Asymmetric envelope (X25519 + Kyber hybrid) | See §PQ section |

**Associated Data (AAD)** on all credential ciphertext must include: `vault_id || credential_id || schema_version` : prevents ciphertext transplantation between vaults or users.

### Hashing

| Purpose | Algorithm |
|---|---|
| OPAQUE verifier | Argon2id (built into OPAQUE) |
| HIBP offline check | SHA-1 (only for k-anonymity prefix matching against HIBP dataset) |
| File / blob integrity | BLAKE3 |
| HMAC / PRF | HMAC-SHA-512 |
| Session token binding | SHA3-256 |
| Audit log chain | BLAKE3 keyed hash |

Never SHA-1 for security-critical operations. SHA-1 appears only for HIBP compatibility (the HIBP dataset is SHA-1 by definition).

### Offline HIBP Password Breach Check

Users' passwords are **never sent over the network** for breach checking.

Instead:
- Download the full HIBP SHA-1 hash list (~40GB) locally, optional at setup
- Build a **Cuckoo filter** (compressed probabilistic set, ~8GB) from the SHA-1 hashes
- On password creation/edit: compute SHA-1(password), query the local Cuckoo filter
- False positive rate ~0.1% : acceptable; no false negatives for set members
- Filter updated on user request via background download, never during vault unlock

The Cuckoo filter file is stored alongside the vault and can be shared between users on the same device.

### Post-Quantum Strategy (hybrid, compile-flag activated)

NIST finalized algorithms:
- **ML-KEM-768** (FIPS 203, formerly Kyber) : key encapsulation
- **ML-DSA-65** (FIPS 204, formerly Dilithium) : digital signatures
- **SLH-DSA** (FIPS 205, formerly SPHINCS+) : stateless hash-based signatures

**Hybrid KEM for VMK backup copies** (e.g., stored on sync server or in FIDO2 passwordless envelope):
```
Combined_Secret = HKDF-SHA3-512(X25519_SharedSecret || ML-KEM-768_SharedSecret)
```
Protects against either algorithm being broken independently.

**CSfC compliance path**: For Commercial Solutions for Classified (CSfC) layered encryption, the double-algorithm approach (ChaCha20 outer + AES inner, or hybrid classical+PQ KEM) maps to the NSA CSfC requirements for two independent encryption layers using approved algorithms. This is the design intent of the double-encryption on OTP secrets and VMK.

**Architecture**: Crypto primitives are behind a trait interface in Rust so PQ can be enabled without structural changes:
```rust
trait KeyEncapsulator {
    fn encapsulate(&self, recipient_pub: &[u8]) -> (Vec<u8>, Vec<u8>); // (ciphertext, shared_secret)
    fn decapsulate(&self, ciphertext: &[u8], sk: &[u8]) -> Vec<u8>;
}
// Classical: X25519KeyEncapsulator
// Hybrid PQ: X25519Kyber768Encapsulator (compile flag: --features pq)
```

---

## 5. Vault Daemon Architecture (Layer 1)

**Language**: Rust (memory safety, no GC pauses, `zeroize` crate for guaranteed key cleanup)

**Static linking**: libsodium, libfido2, SQLCipher, liboqs : no dynamic library substitution attacks.

**IPC**: Unix domain socket (`AF_UNIX`) at `/run/vault-daemon/vault.sock`
- `SO_PEERCRED` on every connection: daemon verifies UID matches the owning user
- Protocol: length-prefixed msgpack frames
- All commands authenticated by session token issued at unlock

**Memory safety**:
- All key material (KEK, VMK, DEKs) allocated in `mlock()`ed pages
- `mprotect(PROT_READ)` after write, `PROT_NONE` when not in use
- `zeroize` crate: guaranteed memory zeroing on Drop, not optimized away
- No key material ever written to disk outside of encrypted SQLite pages
- Swap disabled or encrypted with ephemeral per-boot key (systemd `MemorySwapMax=0` on service)

**Vault file**: Single SQLite file, opened exclusively with SQLCipher
- Page-level AES-256-GCM encryption (each 4KB page independently encrypted)
- Key derived from VMK via HKDF : SQLCipher key is not the VMK itself
- WAL mode disabled when vault is locked; enabled only during active session
- File-level BLAKE3 integrity check on open

**Daemon lifecycle**:
```
start        → listen on socket, vault locked
unlock       → YubiKey challenge → Argon2id → KEK → decrypt VMK → mlock VMK
  session    → issue session token to connecting client
  operations → CRUD on credentials, folders, assets (all in-memory decrypt/encrypt)
lock         → zeroize VMK, KEK, all DEKs from mlock pages → vault locked
stop         → zeroize all, close socket
```

**Idle auto-lock**: Configurable (default 15 minutes), enforced by daemon : not client.

**systemd service** (`/etc/systemd/system/vault-daemon.service`):
```ini
[Service]
Type=notify
User=vault
Group=vault
ExecStart=/usr/local/bin/vault-daemon --socket /run/vault-daemon/vault.sock
RuntimeDirectory=vault-daemon
RuntimeDirectoryMode=0700
MemorySwapMax=0
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
RestrictNamespaces=true
SystemCallFilter=@system-service @memlock
CapabilityBoundingSet=CAP_IPC_LOCK
AmbientCapabilities=CAP_IPC_LOCK
```

**AppArmor profile** (`/etc/apparmor.d/vault-daemon`):
- Allow: read vault file, read HIBP filter, mlock syscall, socket at defined path
- Deny: network access (unless sync enabled), /proc/*/mem, ptrace
- Explicit deny on all other filesystem write paths

---

## 6. Authentication Architecture

### YubiKey Challenge-Response (Primary Unlock)

1. Daemon reads vault UUID from SQLite header (unencrypted metadata)
2. Computes challenge = BLAKE3(vault_uuid || unlock_counter) : 32 bytes
3. Sends challenge to YubiKey slot 2 via `ykpers` / `libfido2`
4. YubiKey returns HMAC-SHA256(slot2_secret, challenge) : 20 bytes
5. Daemon computes: `Argon2id(master_password || yubikey_response, salt, m=256MB, t=3, p=4)` → KEK
6. KEK decrypts VMK from SQLite
7. VMK mlock()ed; KEK immediately zeroized after VMK decryption

**Fallback without YubiKey**: Optional, disabled by default. If enabled, Argon2id params are increased (m=512MB, t=6) to compensate for missing hardware factor.

### FIDO2 / Passkey / U2F

Implemented via `libfido2` in the Rust daemon:
- **Login requirements**: A user can use a traditional master password, but must also be able to add up to 2 registered FIDO2/U2F credentials per vault (to ensure account recovery if one physical key is lost).
- **Passkey support**: Users can set up a Passkey (resident key) for truly passwordless unlock.
- **CTAP2** preferred; CTAP1/U2F supported for legacy keys.
- **Passkey details**: stores an asymmetrically-encrypted copy of VMK on the authenticator's credential blob.
- **U2F hardware key**: second factor after master password (Option A) : password still provides KEK.
- **Passwordless path (Option B)**: VMK encrypted with X25519 key derived from FIDO2 assertion; no master password required at unlock but master password required for VMK rotation.

WebAuthn RP in the optional web frontend (Layer 2) proxies assertions to the daemon.

### TOTP / OTP

- RFC 6238 compliant, 30-second window, 6-digit TOTP
- OTP secret encrypted with VMK inside SQLite
- Backup codes: 10 × 8-char alphanumeric, Argon2id-hashed before storage
- Account-level OTP (vault unlock factor) is separate from per-credential TOTP stored in vault

### Optional Web/Multi-User Mode (OPAQUE)

When deployed as a shared server (self-hosted, multi-user):

**Registration**:
1. Client runs OPAQUE registration with master password → sends OPAQUE record to server
2. Client derives KEK from OPAQUE export key (+ YubiKey response if available client-side)
3. Client generates 256-bit VMK, encrypts with KEK → sends `encrypted_vmk` to server
4. Server stores: OPAQUE record, `encrypted_vmk`, Argon2id params : never the master password

**Login**:
1. Client fetches Argon2id params + OPAQUE challenge
2. OPAQUE finish → session token + export key
3. Client derives KEK → fetches and decrypts `encrypted_vmk` → VMK in memory only

---

## 7. Database Schema

### Local: SQLite + SQLCipher

All tables inside the encrypted vault file. Schema version tracked for migration.

```sql
-- Vault metadata (page 1, header area : unencrypted fields: vault_uuid, schema_version)
CREATE TABLE vault_meta (
  key   TEXT PRIMARY KEY,
  value BLOB NOT NULL   -- encrypted with VMK for sensitive fields
);
-- Keys: 'argon2_salt', 'argon2_params', 'encrypted_vmk', 'vmk_nonce',
--        'unlock_counter', 'created_at', 'hibp_filter_path'

CREATE TABLE users (
  id            TEXT PRIMARY KEY,   -- UUID v4
  email         TEXT UNIQUE NOT NULL,
  first_name    TEXT NOT NULL,
  last_name     TEXT NOT NULL,
  profile_pic   BLOB,               -- stored raw, EXIF stripped, max 2MB
  created_at    INTEGER NOT NULL    -- Unix timestamp
);

CREATE TABLE fido2_credentials (
  id              TEXT PRIMARY KEY,
  credential_id   BLOB UNIQUE NOT NULL,
  public_key_cbor BLOB NOT NULL,
  sign_count      INTEGER NOT NULL DEFAULT 0,
  aaguid          TEXT,
  is_passkey      INTEGER DEFAULT 0,
  encrypted_vmk_copy BLOB,          -- VMK wrapped for passwordless (Option B)
  vmk_copy_nonce  BLOB,
  name            TEXT,
  created_at      INTEGER NOT NULL,
  last_used_at    INTEGER,
  CHECK (rowid <= 2)                -- enforce max 2 keys via trigger
);

CREATE TABLE otp_config (
  id              TEXT PRIMARY KEY,
  encrypted_secret BLOB NOT NULL,   -- VMK-encrypted TOTP secret
  secret_nonce    BLOB NOT NULL,
  backup_codes    BLOB NOT NULL,    -- VMK-encrypted JSON [{hash, used_at}]
  backup_nonce    BLOB NOT NULL,
  created_at      INTEGER NOT NULL
);

CREATE TABLE folders (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  description TEXT,
  icon_svg    TEXT,                 -- DOMPurify-sanitized before insert
  sort_order  INTEGER DEFAULT 0,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE TABLE credentials (
  id             TEXT PRIMARY KEY,
  folder_id      TEXT REFERENCES folders(id),
  encrypted_dek  BLOB NOT NULL,     -- VMK-encrypted 256-bit DEK
  dek_nonce      BLOB NOT NULL,     -- 24 bytes
  ciphertext     BLOB NOT NULL,     -- DEK-encrypted JSON blob
  ct_nonce       BLOB NOT NULL,
  ct_aad         BLOB NOT NULL,     -- vault_id||cred_id||schema_version
  schema_version INTEGER DEFAULT 1,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);
-- Credential JSON blob (plaintext, never stored unencrypted):
-- { platform, url, email, username, password, tags[], kba[], u2f_keys[],
--   otp_secret, notes, phone_numbers[], custom_fields{} }

CREATE TABLE asset_holder (
  id         TEXT PRIMARY KEY,
  ciphertext BLOB NOT NULL,         -- VMK-encrypted JSON
  nonce      BLOB NOT NULL,
  updated_at INTEGER NOT NULL
);
-- Asset JSON: { emails[], phone_numbers[], u2f_key_names[] }

CREATE TABLE audit_log (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        INTEGER NOT NULL,
  action    TEXT NOT NULL,          -- LOGIN_OK, CRED_ADD, CRED_DELETE, etc.
  resource  TEXT,
  prev_hash BLOB NOT NULL,          -- BLAKE3(previous row) : integrity chain
  row_hash  BLOB NOT NULL           -- BLAKE3(this row data)
);
```

### Optional: PostgreSQL (multi-user web deployment only)

Same logical schema as above, adapted to PostgreSQL types (UUID, BYTEA, TIMESTAMPTZ). Add row-level security (RLS) so each user's rows are isolated at the database level. This is only relevant when operating Layer 1 as a shared server, not for local vault use.

---

## 8. Sync Architecture (Optional, Layer 3)

**Cloudflare Zero Trust** (or WireGuard to self-hosted relay) provides the encrypted tunnel.

**What is synced**: The entire SQLite vault file, already encrypted by SQLCipher with AES-256-GCM. The sync layer handles only blob transfer : it has no knowledge of vault contents.

**Sync mechanism**:
1. Daemon computes BLAKE3 hash of current vault file
2. If changed, compresses with zstd and uploads to sync endpoint (S3-compatible or CF R2)
3. On other device: daemon detects newer version, downloads, verifies BLAKE3 hash
4. SQLCipher decryption happens locally : sync server never receives KEK or VMK

**Conflict resolution**: Last-write-wins per device, with vault-level vector clock. On conflict: both versions retained, user prompted to merge via UI.

**What Cloudflare Zero Trust is NOT used for**:
- Authentication : OPAQUE handles this
- Vault data in plaintext : never
- Key exchange : never

---

## 9. API Architecture (Optional Web Frontend)

**Stack**: Rust (Axum) or Node.js + Fastify : depends on whether web frontend shares the daemon process or runs separately.

**Preferred**: The web frontend communicates with the Rust daemon via Unix socket. No separate web backend needed. The web server (Nginx) serves static React assets only; all vault logic routes through the daemon socket.

**Endpoints** (all under `/api/v1/`, HTTPS only, if web mode enabled):

```
POST   /auth/register
POST   /auth/login/init
POST   /auth/login/finish
POST   /auth/logout
POST   /auth/fido2/register
POST   /auth/fido2/authenticate
POST   /auth/otp/setup
POST   /auth/otp/verify

GET    /vault/folders
POST   /vault/folders
PUT    /vault/folders/:id
DELETE /vault/folders/:id

GET    /vault/credentials
POST   /vault/credentials
PUT    /vault/credentials/:id
DELETE /vault/credentials/:id

GET    /vault/assets
PUT    /vault/assets

GET    /user/profile
PUT    /user/profile
POST   /user/profile/picture

GET    /audit/log
```

**All mutating endpoints require**:
- Valid session cookie (`httpOnly`, `Secure`, `SameSite=Strict`)
- Origin header validation (or CSRF double-submit token)
- Request body JSON Schema validation

**Rate limiting**:
- `/auth/login/*`: 5/min per IP, 3/min per account
- `/auth/fido2/*`: 10/min per IP
- General: 300/min per session

---

## 10. Frontend Security (Layer 2)

**React 19 + TypeScript : no key material in browser state.**

**Key Memory Management**:
```typescript
// Keys NEVER enter React state, localStorage, sessionStorage, or IndexedDB
// VMK lives only in the daemon; browser holds only a short-lived session token
class SecureKeyStore {
  #sessionToken: Uint8Array | null = null;

  store(token: Uint8Array): void { this.#sessionToken = token; }
  clear(): void {
    if (this.#sessionToken) { this.#sessionToken.fill(0); this.#sessionToken = null; }
  }
}
// clear() on: logout, pagehide, visibilitychange to hidden, idle timeout
// All crypto operations happen in daemon : browser is display only
```

**SVG Sanitization**: DOMPurify strict config : `FORBID_TAGS: ['script','use','foreignObject']`, `FORBID_ATTR: ['onload','onerror','href','xlink:href']`.

**Image Upload**:
- Validate magic bytes client-side: `FF D8 FF` (JPEG), `00 00 00 XX ftyp` (HEIC)
- Server-side (daemon): re-validate, re-encode with `image` crate (Rust) to strip EXIF
- Stored as encrypted blob inside SQLite vault : never in a separate file server when local

**Content Security Policy**:
```
default-src 'none';
script-src 'self' 'nonce-{per-request}';
style-src 'self';
img-src 'self' blob: data:;
connect-src 'self';
font-src 'self';
form-action 'self';
frame-ancestors 'none';
base-uri 'none';
require-trusted-types-for 'script';
```

**Session**: Idle timeout 15 minutes (enforced by daemon, not browser). Absolute expiry 24 hours. VMK zeroized in daemon on lock : browser session token becomes useless.

---

## 11. Infrastructure & Hardening (Ubuntu 26 LTS)

```
[Local Mode]
User Process → Unix socket → Vault Daemon (Rust) → SQLite+SQLCipher vault file
                                      │
                              mlock()ed key pages
                              AppArmor confined
                              systemd sandboxed

[Optional Web Mode]
Internet ──HTTPS──► Nginx (TLS 1.3, HSTS) → static React assets
                                           → /api/* proxy to Vault Daemon socket
```

**OS Hardening**:
- Unattended-upgrades, automatic security patches
- AppArmor: vault-daemon confined (no network, restricted filesystem)
- UFW: inbound 443/80 only; SSH key-only, non-standard port
- LUKS2 on all data volumes (Argon2id KDF), separate from vault encryption
- Swap: disabled (`/etc/fstab`) or encrypted with ephemeral key (`systemd-swap`)
- Auditd: monitor ptrace, mmap exec, file access to vault paths
- Secure Boot + measured boot (TPM optional but recommended for server deployments)

**YubiKey as Hardware Root** (replaces TPM requirement):
- No TPM required on client machines : YubiKey is the hardware binding
- Server deployments may optionally use TPM to seal the daemon's signing key for systemd attestation
- HSM path: PKCS#11 interface via `pkcs11` crate : drop-in when HSM is available

**Build**:
```makefile
# Static linking : no dynamic library substitution
RUSTFLAGS="-C target-feature=+crt-static"
cargo build --release --features "pq"  # pq = ML-KEM hybrid mode
```

---

## 12. Compliance Alignment

| Standard | Requirement | Implementation |
|---|---|---|
| NIST SP 800-63B | Authenticator assurance levels | AAL2 default (password + YubiKey), AAL3 with FIDO2 hardware key attestation |
| NIST SP 800-132 | Password-based key derivation | Argon2id, m=256MB, t=3, p=4 |
| FIPS 140-3 | Cryptographic module | libsodium FIPS build or OpenSSL 3.x FIPS provider |
| FIPS 203/204/205 | Post-quantum algorithms | ML-KEM-768, ML-DSA-65, SLH-DSA (compile flag) |
| NSA CSfC | Layered encryption for classified | Double-algorithm encryption (ChaCha20 outer + AES-256 inner) on VMK and classified fields |
| NIST SP 800-53 | Security controls | AU (audit chain), IA (OPAQUE + FIDO2), SC (TLS 1.3 + AEAD), SI (BLAKE3 integrity) |
| RFC 9106 | Argon2 parameters | m≥256MB, t≥3, p≥4 |
| W3C WebAuthn Level 3 | FIDO2/Passkey RP | Full attestation verification via libfido2 |
| NIST SP 800-38D | AES-GCM nonce management | XChaCha20 (192-bit nonce) preferred to avoid AES-GCM nonce reuse at scale |

**CSfC-specific note**: The NSA CSfC program requires two independent encryption layers using NSA-approved algorithms. The VMK double-encryption (XChaCha20-Poly1305 outer, AES-256-GCM inner) maps to this. For a full CSfC Package approval, a formal cryptographic module validation (FIPS 140-3 Level 2+) would be required : plan for this from the start by using the OpenSSL FIPS provider rather than libsodium in production builds targeting classified environments.

---

## 13. Directory Structure

```
vault-manager/
├── daemon/                    # Rust vault daemon
│   ├── src/
│   │   ├── main.rs
│   │   ├── crypto/
│   │   │   ├── mod.rs
│   │   │   ├── argon2.rs
│   │   │   ├── xchacha20.rs
│   │   │   ├── aes_gcm.rs
│   │   │   ├── kem.rs         # X25519 + ML-KEM hybrid
│   │   │   └── hibp.rs        # Cuckoo filter
│   │   ├── vault/
│   │   │   ├── mod.rs
│   │   │   ├── db.rs          # SQLCipher operations
│   │   │   ├── credentials.rs
│   │   │   ├── folders.rs
│   │   │   └── assets.rs
│   │   ├── auth/
│   │   │   ├── yubikey.rs     # HMAC-SHA256 challenge-response
│   │   │   ├── fido2.rs       # libfido2 bindings
│   │   │   ├── totp.rs
│   │   │   └── opaque.rs      # Optional multi-user mode
│   │   ├── ipc/
│   │   │   ├── socket.rs      # Unix socket + peercred
│   │   │   └── protocol.rs    # msgpack frame definitions
│   │   ├── sync/
│   │   │   └── cloudflare.rs  # Optional encrypted file sync
│   │   └── audit.rs           # BLAKE3-chained audit log
│   ├── Cargo.toml
│   └── build.rs
├── web/                       # React 19 frontend
│   ├── src/
│   │   ├── main.tsx
│   │   ├── crypto/
│   │   │   └── keystore.ts    # SecureKeyStore : no keys in state
│   │   ├── pages/
│   │   ├── components/
│   │   └── locales/
│   ├── package.json
│   └── vite.config.ts
├── deploy/
│   ├── vault-daemon.service   # systemd unit
│   ├── apparmor.d/
│   │   └── vault-daemon
│   ├── nginx/
│   │   └── vault.conf
│   └── Makefile
└── hibp/
    └── build-filter.sh        # Download HIBP, build Cuckoo filter
```

---

## 14. Build Phases

**Phase 1 : Vault Core (no shortcuts)**:
1. SQLite + SQLCipher integration, schema, migrations
2. Argon2id + YubiKey challenge-response KEK derivation
3. VMK/DEK key hierarchy : XChaCha20-Poly1305
4. mlock()ed SecureKeyStore in Rust with `zeroize`
5. Unix socket IPC with peercred authentication
6. systemd unit + AppArmor profile

**Phase 2 : Auth Hardening**:
1. FIDO2/U2F registration and assertion via libfido2
2. Passkey passwordless VMK envelope (Option B)
3. TOTP 2FA for vault unlock
4. Idle auto-lock + session management in daemon

**Phase 3 : Vault UX**:
1. Credential CRUD with encrypted blobs and DEK rotation
2. Folder management, asset holder
3. React frontend connecting via daemon socket
4. HIBP Cuckoo filter build + local query

**Phase 4 : Hardening and PQ**:
1. Hybrid ML-KEM-768 + X25519 VMK encapsulation (compile flag)
2. BLAKE3-chained audit log
3. Encrypted sync via Cloudflare Zero Trust / WireGuard
4. CSP, HSTS, full security header hardening
5. OpenSSL FIPS provider build target for classified deployments
6. External penetration test

---

## Critical Design Decisions

**Local-first is non-negotiable** for security: no network dependency means no network attack surface during normal vault operations. The vault file is the single source of truth.

**YubiKey replaces TPM as hardware root**: simpler to deploy across heterogeneous client hardware, portable, and proven in production. TPM remains optional for server-side systemd attestation.

**Do not use localStorage for key material**: the web layer (Layer 2) holds only a session token. All keys live in daemon mlock()ed memory. This eliminates the entire localStorage/XSS key exfiltration attack class.

**Offline HIBP via Cuckoo filter**: never send passwords over the network for breach checking. The ~8GB filter is a one-time download; no user action is traceable to a specific password.

**XChaCha20-Poly1305 over AES-GCM as primary**: 192-bit nonce eliminates nonce collision catastrophe under high-volume or multi-device use. AES-GCM's 96-bit nonce requires strict counter management that is difficult to guarantee across sync scenarios.

**Argon2id params must be tuned to hardware at deployment**: target 500ms–1s on the weakest supported device. Too fast = brute force risk on stolen vault file. Too slow = DoS. Params stored in vault header so they can be upgraded without re-encryption.

**CSfC / classified path**: use OpenSSL 3.x FIPS provider from day one in builds targeting classified environments. Libsodium is not FIPS-validated. The FIPS provider supports AES-256-GCM, SHA-3, HMAC-SHA-512, and the ML-KEM/ML-DSA algorithms as of OpenSSL 3.5+.
