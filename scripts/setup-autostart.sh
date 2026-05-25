#!/bin/bash
# PWDnow Autostart Setup Script
# Single-user PM2 setup for autostart.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=> PWDnow Autostart Setup"
echo ""

# Prevent sd-notify from crashing if PM2 inherits an old NOTIFY_SOCKET
unset NOTIFY_SOCKET

# ── Build ─────────────────────────────────────────────────────────────────────
echo "=> Compiling Vault Daemon (release)..."
(cd "${SCRIPT_DIR}/../daemon" && cargo build --release)

# ── Socket directory ──────────────────────────────────────────────────────────
mkdir -p /tmp/vault-daemon-run
chmod 700 /tmp/vault-daemon-run

# ── PM2: daemon ───────────────────────────────────────────────────────────────
echo "=> Starting Vault Daemon via PM2..."
(cd "${SCRIPT_DIR}/../daemon" && pm2 start target/release/vault-daemon \
    --name vault-daemon \
    -- --socket /tmp/vault-daemon-run/vault.sock \
    || pm2 restart vault-daemon --update-env)

# ── PM2: web server ───────────────────────────────────────────────────────────
echo "=> Starting Web Server via PM2..."
(cd "${SCRIPT_DIR}/../web" && pm2 start ecosystem.config.cjs --env production || pm2 restart pwdnow --update-env)

pm2 save

pm2 startup | tail -n 1 > /tmp/pm2_startup.sh
chmod +x /tmp/pm2_startup.sh
sudo bash /tmp/pm2_startup.sh || echo "Note: Run 'pm2 startup' manually if sudo fails."

echo ""
echo "=========================================================="
echo "✅ PM2 is managing PWDnow. Autostart configured successfully!"
echo "=========================================================="
