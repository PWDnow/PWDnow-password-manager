# Vault Manager — Build and deployment Makefile
#
# Usage:
#   make build          — build daemon (classical) + web frontend
#   make build-pq       — build daemon with ML-KEM-768 post-quantum feature + web frontend
#   make test           — run all tests (cargo test + vitest)
#   make install        — install daemon binary, systemd unit, AppArmor profile, nginx config
#   make clean          — remove build artefacts
#
# 'make install' must be run as root (or with sudo).
# 'make build-pq' requires the ml-kem crate; see Cargo.toml [features].

PROJECT_ROOT := $(shell cd .. && pwd)
DAEMON_DIR   := $(PROJECT_ROOT)/daemon
WEB_DIR      := $(PROJECT_ROOT)/web
DEPLOY_DIR   := $(PROJECT_ROOT)/deploy

BINARY       := $(DAEMON_DIR)/target/release/vault-daemon
INSTALL_BIN  := /usr/local/bin/vault-daemon

.PHONY: all build build-pq test install install-daemon install-systemd install-apparmor install-nginx install-hibp clean

all: build

# ── Build ─────────────────────────────────────────────────────────────────────

build:
	@echo "==> Building vault-daemon (classical)..."
	cd $(DAEMON_DIR) && cargo build --release
	@echo "==> Building web frontend..."
	cd $(WEB_DIR) && npm run build
	@echo "==> Build complete."

build-pq:
	@echo "==> Building vault-daemon with ML-KEM-768 post-quantum support..."
	cd $(DAEMON_DIR) && cargo build --release --features pq
	@echo "==> Building web frontend..."
	cd $(WEB_DIR) && npm run build
	@echo "==> PQ build complete."

# ── Test ─────────────────────────────────────────────────────────────────────

test:
	@echo "==> Running daemon tests..."
	cd $(DAEMON_DIR) && cargo test
	@echo "==> Running frontend tests..."
	cd $(WEB_DIR) && npm run test -- --run
	@echo "==> All tests passed."

lint:
	@echo "==> Checking daemon (clippy)..."
	cd $(DAEMON_DIR) && cargo clippy -- -D warnings
	@echo "==> Checking frontend (tsc)..."
	cd $(WEB_DIR) && npm run lint

# ── Install ───────────────────────────────────────────────────────────────────

install: build install-daemon install-systemd install-apparmor install-nginx
	@if [ "$(HIBP)" = "1" ]; then $(MAKE) install-hibp; fi
	@echo "==> Installation complete."
	@echo "    Start with: systemctl enable --now vault-daemon"

install-daemon:
	@echo "==> Installing vault-daemon binary to $(INSTALL_BIN)..."
	install -Dm755 $(BINARY) $(INSTALL_BIN)

install-systemd:
	@echo "==> Installing systemd unit..."
	install -Dm644 $(DEPLOY_DIR)/vault-daemon.service /etc/systemd/system/vault-daemon.service
	systemctl daemon-reload

install-apparmor:
	@echo "==> Installing AppArmor profile..."
	install -Dm644 $(DEPLOY_DIR)/apparmor.d/vault-daemon /etc/apparmor.d/vault-daemon
	apparmor_parser -r /etc/apparmor.d/vault-daemon

install-nginx:
	@echo "==> Installing nginx config..."
	install -Dm644 $(DEPLOY_DIR)/nginx/vault.conf /etc/nginx/sites-available/vault.conf
	ln -sf /etc/nginx/sites-available/vault.conf /etc/nginx/sites-enabled/vault.conf
	nginx -t
	systemctl reload nginx

# ── HIBP filter install (opt-in: make install HIBP=1) ────────────────────────
#
# Builds and installs the offline HIBP Cuckoo filter.  This is a one-time
# multi-hour operation; omit HIBP=1 on normal installs.
#
# Requires: bash, python3, curl, awk, sha256sum
# Output:   /var/lib/vault-daemon/hibp.cuckoo  (0640, vault:vault)
#           /var/lib/vault-daemon/hibp.cuckoo.sha256  (sidecar, same perms)

HIBP_OUTPUT := /var/lib/vault-daemon/hibp.cuckoo

install-hibp:
	@echo "==> Building HIBP Cuckoo filter (this may take several hours)..."
	mkdir -p /var/lib/vault-daemon
	HIBP_OUTPUT=$(HIBP_OUTPUT) bash $(PROJECT_ROOT)/hibp/build-filter.sh
	@echo "==> Setting permissions on HIBP filter..."
	chown vault:vault $(HIBP_OUTPUT) $(HIBP_OUTPUT).sha256
	chmod 0640 $(HIBP_OUTPUT) $(HIBP_OUTPUT).sha256
	@echo "==> HIBP filter installed at $(HIBP_OUTPUT)"

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:
	@echo "==> Cleaning daemon build artefacts..."
	cd $(DAEMON_DIR) && cargo clean
	@echo "==> Cleaning web build artefacts..."
	cd $(WEB_DIR) && npm run clean
	@echo "==> Clean complete."
