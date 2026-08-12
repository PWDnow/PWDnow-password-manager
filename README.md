<div align="center">

# PWDnow

Zero-knowledge, local-first password manager

[![CI](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml)
[![Security Audit](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml)
[![Coverage](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml)
[![Mutation Testing](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[Report a bug](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Request a feature](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Security policy](#security-policy)

</div>

<div align="center">

**Read this in other languages**

| | | | |
|---|---|---|---|
| English | [Français](docs/i18n/README.fr.md) | [Español](docs/i18n/README.es.md) | [Deutsch](docs/i18n/README.de.md) |
| [Italiano](docs/i18n/README.it.md) | [Português](docs/i18n/README.pt.md) | [Русский](docs/i18n/README.ru.md) | [العربية](docs/i18n/README.ar.md) |
| [हिन्दी](docs/i18n/README.hi.md) | [中文](docs/i18n/README.zh.md) | [日本語](docs/i18n/README.ja.md) | [한국어](docs/i18n/README.ko.md) |
| [Bahasa Indonesia](docs/i18n/README.id.md) | | | |

</div>

---

## About

PWDnow is a password manager built on a simple premise: the server, the browser, and the network in between should never see a plaintext secret. All cryptographic operations run inside a dedicated Rust daemon on the machine the vault lives on. The web interface, whether opened locally or served to a browser, only ever exchanges opaque encrypted blobs with that daemon. There is no cloud sync by default, no telemetry, and no vendor that can be compelled to hand over your data, because the vendor never has it.

The project is split into two layers that communicate over a local IPC channel:

- **Vault Daemon** (`daemon/`), written in Rust: key derivation, encryption, decryption, SQLCipher storage, memory locking, and zeroization. This is the only part of the system that ever touches a plaintext key or a plaintext credential.
- **Web Interface** (`web/`), a React 19 single-page application served by an Express process: renders the UI, forwards encrypted requests to the daemon over a Unix domain socket, and never holds key material outside of a short-lived, memory-only session token.

PWDnow can run entirely offline on a single machine, or be deployed behind Nginx with TLS for LAN or self-hosted server access. Either way, the trust boundary is the same: your master password and your data never leave the daemon's protected memory.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [Supported Platforms](#supported-platforms)
- [Getting Started](#getting-started)
  - [Quick Install](#quick-install)
  - [Building from Source](#building-from-source)
  - [Configuration](#configuration)
- [Usage](#usage)
- [Development](#development)
- [Testing](#testing)
- [Deployment](#deployment)
- [Security Policy](#security-policy)
- [Contributing](#contributing)
- [License](#license)

## Features

**Core vault**
- Folder-based credential organization with drag-to-reorder
- Password, TOTP secret, notes, and custom-field storage per credential
- Password strength scoring, reuse detection, and common-password detection
- Offline breach checking against a local Cuckoo-filter build of the Have I Been Pwned password corpus, no per-lookup network call required
- Asset holder view: a consolidated list of every email address, phone number, and hardware security key registered across your credentials

**Authentication and MFA**
- WebAuthn and FIDO2 support for hardware security keys and platform authenticators (Touch ID, Windows Hello)
- TOTP (RFC 6238) and HOTP (RFC 4226) generation, with replay protection
- Passwordless login through synced or device-bound passkeys
- Configurable per-account MFA enforcement

**Security modes**
- Duress mode: unlocking with a designated alternate password triggers a forensic wipe instead of granting access
- Travel mode: hides a chosen subset of credentials behind a separate password before crossing a border or handing over a device
- Exponential backoff lockout after repeated failed unlock attempts
- Emergency access: grant a trusted contact time-delayed access to your vault in case you become unreachable

**Import and export**
- Native `.p2w` format: a double-AEAD encrypted, padded, metadata-obfuscated export designed to resist offline tampering and traffic analysis
- Plain JSON, CSV, and KeePass-compatible XML export and import
- Import from Bitwarden, 1Password (CSV, 1PUX), and NordPass exports

**Post-quantum and standards-grade cryptography**
- Hybrid X25519 + ML-KEM-768/1024 key encapsulation (on by default, not an opt-in flag)
- ML-DSA-87 post-quantum signatures
- Argon2id key derivation, AES-256-GCM and XChaCha20-Poly1305 authenticated encryption
- Optional CNSA 2.0 strict mode, which restricts the daemon to the NSA's Commercial National Security Algorithm Suite (SHA-384 HKDF, PBKDF2-SHA-512, and removal of BLAKE3, SHA3, XChaCha20, Ed25519, and X25519 from active code paths)

## Architecture

```
┌─────────────────────────────┐        Unix socket        ┌──────────────────────────────┐
│   Web Interface (web/)      │  msgpack over /run/...    │   Vault Daemon (daemon/)     │
│   React 19 + Express        │ ─────────────────────────▶│   Rust, SQLCipher, mlock()   │
│   Zero-knowledge UI          │◀─────────────────────────  │   Argon2id, AES-256-GCM,     │
│   Session token only, no keys│      encrypted responses  │   XChaCha20-Poly1305,        │
└─────────────────────────────┘                            │   hybrid PQ KEM               │
                                                             └──────────────────────────────┘
```

The daemon exposes a strongly typed request and response protocol (`daemon/src/ipc/protocol.rs`), transported as MessagePack frames over a Unix domain socket. Every authenticated request carries a session token that the daemon validates before touching the database. The daemon also verifies the identity of the connecting process at the OS level (`SO_PEERCRED`), so only the trusted web proxy, running as the correct system user, can reach it.

The web layer never receives a master key, key-encryption key, vault master key, or data-encryption key in any form. It receives ciphertext and forwards it. A companion monitoring daemon (`monitor/`) tracks memory growth, disk usage, and process health independently of the vault daemon itself, so a memory leak or a stuck process is caught and alerted on rather than silently degrading the service.

Full technical detail, including the key derivation hierarchy, the P2W file format specification, and the threat model, is documented in [`architecture.md`](architecture.md).

## Security Model

PWDnow assumes the network, the browser process, and the host operating system are all potentially hostile, and designs around that assumption rather than around a friendlier default.

- **Zero-knowledge by construction**: the browser cannot leak what it never had. Master keys and derived keys exist only inside the daemon's address space.
- **Memory protection**: the vault master key is held in a locked memory region (`mlock`) that is sealed with `mprotect(PROT_NONE)` while idle, and wiped with the `zeroize` crate as soon as it is no longer needed.
- **At-rest encryption**: the vault database is SQLCipher-encrypted end to end. Exports use double AEAD (an inner AES-256-GCM layer and an outer XChaCha20-Poly1305 layer) with the header bound into both authentication tags.
- **Independent verification**: the project runs continuous mutation testing and chaos testing in CI, in addition to standard unit and end-to-end suites, specifically to catch tests that pass without actually verifying the behavior they claim to cover.

If you find a vulnerability, see [Security Policy](#security-policy) before opening a public issue.

## Supported Platforms

PWDnow is developed and tested primarily on **Ubuntu 26.04 LTS (Resolute)**. The installer additionally detects and supports:

- Debian and Debian-derived distributions (Ubuntu, Linux Mint, Pop!_OS, Zorin, Kali)
- Fedora and RHEL-family distributions (Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux)

Both `x86_64` and `aarch64` targets are supported by the Rust toolchain. Other Linux distributions may work but are not part of the regular test matrix. There is currently no macOS or Windows build.

## Getting Started

### Quick Install

```bash
git clone https://github.com/PWDnow/PWDnow-password-manager.git
cd PWDnow
./install.sh
```

The installer detects your distribution, checks and offers to install missing dependencies, audits your SSH configuration, checks for port conflicts, builds the daemon and the web frontend from source, and installs both as systemd services running under dedicated unprivileged system users. Nothing is installed with elevated privileges beyond what systemd, AppArmor, and package installation require, and every privileged step is shown before it runs.

### Building from Source

Requirements: Node.js 24 or newer, Rust 1.94 or newer (pinned in `daemon/rust-toolchain.toml`), `protoc`, and the development headers for `libsodium`, `sqlcipher`, and `libfido2`.

```bash
# Daemon
cd daemon
cargo build --release
cargo test

# Web
cd web
npm install
npm run build
npm start
```

Or, from `deploy/`:

```bash
make build          # daemon + web, release mode
make test            # cargo test + vitest
make install          # install binary, systemd units, AppArmor profile, and nginx config (requires sudo)
```

Post-quantum key encapsulation is enabled by default. `make build-pq` and `cargo build --release --features pq-hybrid-1024` are kept as explicit aliases of the same default build, for clarity and for compatibility with older documentation. Pass `--features cnsa-strict` for CNSA 2.0 strict mode.

### Configuration

Copy `web/.env.example` to `web/.env` and adjust as needed:

| Variable | Purpose |
|---|---|
| `DAEMON_GRPC_ADDR` | Address the web layer uses to reach the daemon (default `127.0.0.1:50051`) |
| `VAULT_ORIGIN` | Allowed browser origin in production, used for WebSocket origin checks |
| `BIND_HOST` | Interface the web server binds to (default `127.0.0.1`; set to `0.0.0.0` for LAN access) |
| `SSL`, `SSL_PORT`, `SSL_DIR` | Optional self-signed HTTPS, generated by `web/scripts/generate-ssl.sh` |

## Usage

On first run, `Setup.tsx` walks through vault creation: choose a master password, optionally register a hardware security key or TOTP, and the daemon creates an encrypted SQLCipher database plus a plaintext sidecar file that records only what the login page needs (which MFA methods are configured, whether password login is even enabled) so nothing has to be decrypted before you have authenticated.

From there:

- Organize credentials into folders, tag custom fields, and generate strong passwords in place
- Enable duress mode and travel mode from Settings if you want a plausible, safe state to present under coercion or at a border crossing
- Run the built-in breach monitor to check your stored passwords against a local, offline copy of known breached passwords, with no outbound query per password
- Export a `.p2w` file for backup, or import from another password manager, without ever leaving your machine

## Development

Repository layout:

```
PWDnow/
├── daemon/     Rust vault daemon. All cryptography lives here.
├── web/        React 19 + Express frontend and IPC proxy.
├── monitor/    Independent Rust process health and memory-leak monitor.
├── deploy/     systemd units, AppArmor profile, Nginx config, Makefile.
├── proto/      gRPC/protobuf definitions shared by daemon and web.
└── hibp/       Script that builds the offline HIBP Cuckoo filter.
```


## Testing

```bash
# Daemon
cd daemon && cargo test
cargo test -- <test_name>       # run a single test

# Web unit tests
cd web && npm run test
npx vitest run src/utils/crypto.test.ts   # single file

# End-to-end (Playwright)
cd web && npx playwright test
npx playwright test e2e/comprehensive-platform.spec.ts   # full regression walkthrough
```

CI runs unit tests, end-to-end tests, dependency auditing, mutation testing, and chaos testing on every push and pull request. `web/e2e/comprehensive-platform.spec.ts` is the regression gate: it walks authentication (success and failure paths), navigation, folder and credential CRUD, duress mode, and account destruction, and should pass before any frontend or authentication change ships.

## Deployment

For anything beyond a single local machine, put Nginx in front of the Express process:

- `deploy/nginx/vault.conf` handles TLS termination, HSTS, and rate limiting. Nginx must not set its own Content-Security-Policy header, since the Express server injects a fresh per-request nonce.
- `deploy/vault-daemon.service` runs the daemon as a dedicated `vault` system user, with `MemorySwapMax=0`, `NoNewPrivileges`, `PrivateTmp`, and only the `CAP_IPC_LOCK` capability it needs for memory locking.
- `deploy/apparmor.d/vault-daemon` confines the daemon's filesystem and capability access at the kernel level, and applies unmodified on both `x86_64` and `aarch64` hosts.

`make install` (or `install.sh` for a full guided install) wires all of this up, including loading the AppArmor profile and enabling the systemd units.

## Security Policy

PWDnow handles credentials, so a vulnerability report here matters more than in most projects. If you find a security issue, please do not open a public issue. Instead, use GitHub's private vulnerability reporting for this repository, or contact the maintainers directly. Include enough detail to reproduce the issue and, if possible, an assessment of impact. We will acknowledge reports promptly and credit reporters who want to be credited once a fix ships.

## Contributing

Issues and pull requests are welcome. Before submitting a change:

- Run `make lint` (`cargo clippy -D warnings` and `tsc --noEmit`) and `make test`
- For frontend or authentication changes, run the full Playwright regression suite
- Keep cryptographic changes in the daemon only; the web layer must never gain access to key material as a side effect of a feature change

## License

PWDnow is released under the [MIT License](LICENSE).
