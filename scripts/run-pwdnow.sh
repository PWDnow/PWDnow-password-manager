#!/bin/bash
# PWDnow Senior Dev Run Script
# Orchestrates the vault daemon and web frontend for development and production.

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON_DIR="$PROJECT_ROOT/daemon"
WEB_DIR="$PROJECT_ROOT/web"
SOCKET_PATH="/tmp/vault-dev.sock"
VAULT_DB="$PROJECT_ROOT/daemon_data/vault.db"

# PID files so cleanup only kills processes we started, not every node/daemon on the system.
DAEMON_PID_FILE="/tmp/pwdnow-daemon.pid"
WEB_PID_FILE="/tmp/pwdnow-web.pid"

cleanup() {
    echo "==> Cleaning up project processes..."
    # Graceful SIGTERM to daemon (allows SQLite WAL checkpoint before exit)
    if [ -f "$DAEMON_PID_FILE" ]; then
        kill -TERM "$(cat "$DAEMON_PID_FILE")" 2>/dev/null || true
        rm -f "$DAEMON_PID_FILE"
    fi
    # Graceful SIGTERM to web server (allows in-flight WS to drain)
    if [ -f "$WEB_PID_FILE" ]; then
        kill -TERM "$(cat "$WEB_PID_FILE")" 2>/dev/null || true
        rm -f "$WEB_PID_FILE"
    fi
    rm -f "$SOCKET_PATH"
}
trap cleanup EXIT
cleanup # Kill any leftover processes from a previous run

echo "==> PWDnow Startup Sequence Initiated"

# 1. Check dependencies
command -v cargo >/dev/null 2>&1 || { echo >&2 "Rust (cargo) is required. Aborting."; exit 1; }
command -v node >/dev/null 2>&1 || { echo >&2 "Node.js is required. Aborting."; exit 1; }

# 2. Build Daemon if missing or changed
echo "==> Building Vault Daemon..."
(cd "$DAEMON_DIR" && cargo build)

# 3. Build Web if dist missing
if [ ! -d "$WEB_DIR/dist" ]; then
    echo "==> Building Web Frontend..."
    (cd "$WEB_DIR" && npm install && npm run build)
fi

# 4. Start Vault Daemon
echo "==> Starting Vault Daemon on $SOCKET_PATH..."
mkdir -p "$(dirname "$VAULT_DB")"
(cd "$DAEMON_DIR" && cargo run -- --socket "$SOCKET_PATH" --vault "$VAULT_DB") &
DAEMON_PID=$!
echo "$DAEMON_PID" > "$DAEMON_PID_FILE"

# Wait for socket
for i in {1..10}; do
    if [ -S "$SOCKET_PATH" ]; then
        break
    fi
    sleep 0.5
done

if [ ! -S "$SOCKET_PATH" ]; then
    echo "==> Error: Vault Daemon failed to start."
    exit 1
fi

# 5. Start Web Server
echo "==> Starting Web Server..."
export VAULT_SOCKET="$SOCKET_PATH"
export NODE_ENV="development"
(cd "$WEB_DIR" && npm start) &
WEB_PID=$!
echo "$WEB_PID" > "$WEB_PID_FILE"

wait
