#!/usr/bin/env bash
# pwdnow-alert.sh — SLA G4: dispatch a single alert about a failing systemd unit.
#
# Usage: pwdnow-alert <unit-name>
#
# Behaviour:
#   * Always logs the failure to the journal with severity ERROR.
#   * If PWDNOW_ALERT_WEBHOOK is set in /etc/default/pwdnow-alert (or the env),
#     fires a JSON webhook with: unit, host, last_5_log_lines, timestamp.
#   * Never blocks systemd: 5-second timeout on the HTTP call.
#
# Why: the existing backup/verify/restore-drill units have comments saying
# "wire an alert" but no actual wiring. This is that wiring.

set -euo pipefail

UNIT="${1:?usage: pwdnow-alert <unit>}"
HOST="$(hostname)"
TS="$(date -Iseconds)"

# Tail the failing unit so the alert is actionable, not just a "something broke".
LOG_TAIL="$(journalctl -u "$UNIT" --no-pager --since=-5min -n 5 -o cat 2>/dev/null || echo '')"

# Always log to journal — this is the floor-level guarantee.
logger -p user.error -t pwdnow-alert "unit=$UNIT host=$HOST FAILED: $LOG_TAIL"

if [ -n "${PWDNOW_ALERT_WEBHOOK:-}" ]; then
    BODY=$(printf '{"unit":"%s","host":"%s","ts":"%s","tail":%s}' \
              "$UNIT" "$HOST" "$TS" \
              "$(printf '%s' "$LOG_TAIL" | jq -Rs . 2>/dev/null || printf '"%s"' "$(echo "$LOG_TAIL" | tr -d '"')")")
    curl --silent --show-error --max-time 5 \
         -X POST -H 'Content-Type: application/json' \
         -d "$BODY" \
         "$PWDNOW_ALERT_WEBHOOK" >/dev/null 2>&1 || \
        logger -p user.warn -t pwdnow-alert "webhook delivery failed"
fi

exit 0
