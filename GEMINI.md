# Gemini Rules for PWDnow

## Project Overview
PWDnow is a highly secure, two-layer password manager.
1. **Layer 1 (Daemon):** A Rust-based daemon (`daemon/`) that handles all cryptographic operations, SQLite + SQLCipher storage, and IPC. It runs completely offline and uses a Unix domain socket (`/run/vault-daemon/vault.sock`) with `SO_PEERCRED` for authentication.
2. **Layer 2 (Web):** A React 19 SPA frontend (`web/`) with TypeScript, Vite, Tailwind CSS v4, and React Router v7. It is served by a minimal Express server (`web/server.js`) that also acts as a WebSocket proxy to the daemon.

## Critical Security Guidelines
- **Zero-Knowledge Architecture:** The web frontend must **NEVER** see or handle plaintext master keys, KEKs, VMKs, or DEKs.
- **Key Material Storage:** NEVER put key material into React state, `localStorage`, `sessionStorage`, or IndexedDB.
- **Session Tokens:** The `SecureKeyStore` class (`web/src/crypto/keystore.ts`) holds the session token in a JS private field. It must be cleared on `pagehide`, `visibilitychange -> hidden`, and logout.
- **Daemon Cryptography:** All encryption, decryption, and OTP generation MUST occur inside the Rust daemon. The browser should only receive opaque JSON blobs.
- **Memory Safety (Rust):** All key material must be allocated in `mlock()`ed pages and guaranteed to be zeroized on drop using the `zeroize` crate.

## Development Workflows & Commands

### Full Project (from `deploy/`)
- `make build` : Builds both daemon (`cargo build --release`) and web (`npm run build`).
- `make build-pq` : Builds with post-quantum hybrid KEM (`--features pq`).
- `make test` : Runs all tests (`cargo test` + `vitest run`).
- `make lint` : Runs linters (`cargo clippy -D warnings` + `tsc --noEmit`).

### Layer 1: Vault Daemon (`daemon/`)
- Build: `cargo build` (use `--release` for production, `--features pq` for post-quantum).
- Test: `cargo test` (run single test: `cargo test -- <test_name>`).
- Lint: `cargo clippy -- -D warnings`.

### Layer 2: Web Frontend (`web/`)
- Install: `npm install`
- Dev Server: `npm run dev` (Vite dev server on port 3000).
- Build: `npm run build`
- Start Prod: `npm start` (Express server).
- Test: `npm run test` (Vitest).
- Lint: `npm run lint` (`tsc --noEmit`).

## Architecture & Code Conventions

### Adding a New Daemon Command
When adding a new IPC command between the web and daemon layers, you MUST update all three locations:
1. `daemon/src/ipc/protocol.rs`: Add variants to `Request` and `Response` enums.
2. `daemon/src/ipc/socket.rs`: Add a match arm in the `dispatch()` function.
3. `web/src/utils/daemonClient.ts`: Add a strictly typed method on the `DaemonClient` class.

### Frontend (React/Web) Conventions
- **State Management:** Use the four built-in React Contexts (`VaultContext`, `UserContext`, `ThemeContext`, `NotificationContext`) located in `src/main.tsx`. **Do not use Redux or Zustand.**
- **Styling:** The project uses **Tailwind CSS v4**. It is explicitly permitted to use Tailwind here, overriding default generic agent guidelines.
- **Icons & Animations:** Use `lucide-react` for standard icons. Use `motion` (Framer Motion) for animations (e.g., page transitions, modals, `Reorder` for drag-and-drop).
- **SVGs:** Any custom SVG data (e.g., stored in `Folder.customSvg`) MUST be sanitized with DOMPurify before rendering.
- **i18n:** Use `useTranslation()` from `react-i18next` for all user-facing strings.
- **Environment:** API keys and environment variables are injected via `vite.config.ts`. The Express server (`server.js`) injects per-request CSP nonces. Nginx handles TLS and must not set duplicate CSP headers.

### Backend (Rust/Daemon) Conventions
- **Features:** The codebase supports optional features like `--features pq` (ML-KEM-768 hybrid KEM) and `--features mock-fido2`.
- **IPC Auth:** Every authenticated daemon request must include a `session_token`. Validate UID + token using the `auth_then!` macro before accessing the database.

## Graphify Knowledge Graph
- The project maintains an AST-based knowledge graph in `web/graphify-out/`.
- Before answering complex architecture or codebase questions, read `web/graphify-out/GRAPH_REPORT.md` for context on god nodes and community structures.
- **Post-Modification:** After modifying code files, run `graphify update .` to keep the graph current.
