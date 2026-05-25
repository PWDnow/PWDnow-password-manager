#!/usr/bin/env bash
# nginx-safe-reload.sh — SLA G9: never reload nginx with a broken config.
#
# The default `systemctl reload nginx` exits 0 even when the new config is
# invalid (it logs and keeps running the OLD config). Operators then assume
# the new config is live; the next master process restart picks up the broken
# file and the service goes down. This wrapper makes invalid configs fail
# LOUDLY at reload time so the bad change is rolled back immediately.
#
# Wire into systemd by dropping a one-line override on the nginx unit:
#   /etc/systemd/system/nginx.service.d/safe-reload.conf
#   ----------------------------------------------------------
#   [Service]
#   ExecReload=
#   ExecReload=/usr/local/sbin/nginx-safe-reload
#   ----------------------------------------------------------
#
# Idempotent and side-effect-free on failure.

set -euo pipefail

if ! nginx -t 2>&1; then
    echo "[nginx-safe-reload] config test FAILED — refusing reload, old config still in effect" >&2
    exit 1
fi

# Use the same signal nginx itself uses for reload (SIGHUP), via the master pid
# file so we don't depend on `systemctl` (avoids re-entry if invoked from a
# systemd ExecReload= override).
PID_FILE="${NGINX_PID:-/run/nginx.pid}"
if [ ! -r "$PID_FILE" ]; then
    echo "[nginx-safe-reload] cannot read $PID_FILE — is nginx running?" >&2
    exit 1
fi
kill -HUP "$(cat "$PID_FILE")"
echo "[nginx-safe-reload] reload signalled (SIGHUP → $(cat "$PID_FILE"))"
