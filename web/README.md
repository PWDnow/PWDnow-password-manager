# PWDnow Web

React 19 + Express frontend and IPC proxy for the PWDnow vault daemon.


## Quick start

```bash
npm install
cp .env.example .env
npm run dev
```

This starts the Vite dev server on port 3000 with hot module reload. It does not require the vault daemon to be running for basic UI work, but daemon-backed features (unlock, credential CRUD, MFA) need `vault-daemon` running and reachable at the address configured in `.env`.

For a production build:

```bash
npm run build
npm start
```
