# PWDnow Web: Gemini Code Instructions

This file serves as your scoped context when modifying the `web/` directory. Note that the root `GEMINI.md` holds broad project rules; this file focuses specifically on the React frontend and its interaction with the daemon/server. Do not use emojis in your responses or outputs.

## Project Context
PWDnow Web is a high-security React 19 SPA. It serves as Layer 2 to the Rust vault daemon and supports a fully self-hosted server fallback mode.

## Critical Security Constraints
- **Zero-Knowledge Principle**: The frontend must never handle plaintext master keys or DEKs.
- **State Management**: Key material (like session tokens) MUST NEVER be stored in React state, `localStorage`, `sessionStorage`, or IndexedDB. Use `SecureKeyStore` class in `src/crypto/keystore.ts` which uses a JS private field (`#token`).
- **DOM Security**: `require-trusted-types-for 'script'` is active. Inject CSP nonces into scripts dynamically via the Express backend. Never add `'unsafe-inline'`.
- **Sanitization**: Any user-provided SVG data (e.g. custom folder icons) must be sanitized with DOMPurify.
- **External Dependencies**: Never bake API keys into Vite using `define`. External API logic must be routed through the server proxy.

## Architecture
The application runs in three modes based on authentication state, managed in `VaultContext.tsx`:
1. **Daemon Mode**: Guarded by `keyStore.hasToken`. Stores securely inside the Rust daemon.
2. **Server Mode**: Guarded by `_pwd_csrf` cookie. Routes API calls through REST in `auth.js`.
3. **Unauthenticated**: Redirects to `/login`.

## Engineering Standards
- **Frameworks**: React 19, Vite, TypeScript, React Router v7.
- **Styling**: Tailwind CSS v4 is used exclusively.
- **State**: Strictly use React Context for global state (`VaultContext`, `UserContext`, `ThemeContext`, `NotificationContext`). No Redux, no Zustand.
- **Animations**: Use `motion` (Framer Motion). For drag-and-drop lists, use `Reorder`.
- **Localization**: Use `react-i18next` for all user-visible strings.
- **Paths**: Use the `@/` alias for absolute imports mapping to `web/`.
- **Testing**: Use `npx playwright test e2e/comprehensive-platform.spec.ts` for a full system walkthrough.

## Comprehensive Platform Test
The file `e2e/comprehensive-platform.spec.ts` provides a high-signal, end-to-end verification of:
1. Login success/failure.
2. Security & Health audits.
3. Language toggle (EN <-> FR) behavior.
4. Asset Holder templates.
5. Folder CRUD operations.
6. Duress Mode (Forensic Wipe) and account destruction state.

Run this test after any major code changes to ensure no core functionality is broken.

## Graphify Knowledge Graph
- Read `graphify-out/GRAPH_REPORT.md` before answering complex architecture queries.
- Run `graphify update .` after code modifications to keep the AST graph current.