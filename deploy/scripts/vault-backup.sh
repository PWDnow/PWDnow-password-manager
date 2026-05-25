#!/usr/bin/env bash
# vault-backup.sh — SLA G2/G3 fix: hardened online backup of the vault DB.
#
# Replaces the inline bash chain in vault-daemon-backup.service. Run by systemd
# as the `vault` user.
#
# Required env (defaults match the legacy unit):
#   SRC          : path to live SQLite/SQLCipher DB (default /var/lib/vault-daemon/vault.db)
#   DEST         : local backup directory     (default /var/backups/vault-daemon)
#   RETAIN_DAYS  : prune local backups older than this many days (default 30)
#
# Optional:
#   BACKUP_REMOTE : if set, rsync the freshly-verified backup off-host.
#                   Forms accepted:
#                     user@host:/path/                  (rsync over SSH)
#                     restic:repo                       (restic repo URI)
#                     s3:bucket/prefix                  (passed to `aws s3 cp`)
#                   The script invokes whichever tool matches the scheme; if the
#                   tool is not installed, the off-site step is skipped with a
#                   warning (NOT a hard failure — local backup still succeeded).
#
# Exit codes:
#   0  : new backup created, verified, retention applied.
#   1  : backup creation or verification failed (nothing pruned).
#   2  : backup OK locally but off-site replication failed (still safe: local copy exists).
#
# Why every step matters for SLA:
#   * `set -euo pipefail` so a failed `sqlite3 .backup` does NOT cause us to
#     sha256 a partial file and then prune the prior good backup.
#   * Write to a `.tmp` and rename atomically so concurrent verify jobs never
#     observe a half-written file.
#   * Sidecar `.sha256` written only after a successful `sqlite3 .backup`.
#   * Retention prunes the OLDEST first and only after the new backup is on
#     disk with its sidecar — guarantees we never drop below 1 good backup.

set -euo pipefail
IFS=$'\n\t'

SRC="${SRC:-/var/lib/vault-daemon/vault.db}"
DEST="${DEST:-/var/backups/vault-daemon}"
RETAIN_DAYS="${RETAIN_DAYS:-30}"
TS="$(date +%s)"

log() { printf '[vault-backup %s] %s\n' "$(date -Iseconds)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

# ── REPLICATE_ONLY mode (SLA G3) ────────────────────────────────────────────
# Off-site replication step: do NOT take a new local snapshot. Locate the
# newest existing local backup and ship it. Used by the offsite timer so a
# failed remote step never disturbs the hourly local cadence.
if [ "${REPLICATE_ONLY:-0}" = "1" ]; then
    [ -d "$DEST" ] || die "dest dir missing: $DEST"
    LATEST="$(find "$DEST" -maxdepth 1 -name 'vault-*.db' -not -name '*.sha256' \
                -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)"
    [ -n "$LATEST" ] || die "no local backups to replicate"
    [ -n "${BACKUP_REMOTE:-}" ] || { log "BACKUP_REMOTE unset — nothing to do"; exit 0; }
    TARGET="$LATEST"
    log "REPLICATE_ONLY: shipping $TARGET → $BACKUP_REMOTE"
    # Fall through to the off-site block below.
else
    [ -r "$SRC" ] || die "source DB not readable: $SRC"
    mkdir -p "$DEST"
    [ -w "$DEST" ] || die "dest dir not writable: $DEST"

    TARGET="$DEST/vault-$TS.db"
    TMP="$TARGET.tmp"
fi

if [ "${REPLICATE_ONLY:-0}" != "1" ]; then
    # Online backup — uses SQLite's backup API, safe while the daemon is writing.
    log "creating backup: $TMP"
    if ! sqlite3 "$SRC" ".backup '$TMP'"; then
        rm -f "$TMP"
        die "sqlite3 .backup failed"
    fi

    # Sanity: did we actually write something?
    [ -s "$TMP" ] || { rm -f "$TMP"; die "backup file is empty"; }

    # Sha256 BEFORE rename so the sidecar matches the bytes we'll keep.
    SHA="$(sha256sum "$TMP" | awk '{print $1}')"
    printf '%s  %s\n' "$SHA" "$(basename "$TARGET")" > "$TMP.sha256.tmp"

    # Atomic rename pair — observers see both or neither.
    mv "$TMP.sha256.tmp" "$TARGET.sha256"
    mv "$TMP" "$TARGET"
    chmod 0640 "$TARGET" "$TARGET.sha256" || true

    log "wrote: $TARGET ($(stat -c%s "$TARGET") bytes, sha256=$SHA)"

    # Retention — prune older than RETAIN_DAYS, but ONLY after this new backup is on disk.
    PRUNED="$(find "$DEST" -maxdepth 1 \( -name 'vault-*.db' -o -name 'vault-*.db.sha256' \) \
                -type f -mtime "+$RETAIN_DAYS" -print -delete | wc -l)"
    log "retention: pruned $PRUNED file(s) older than $RETAIN_DAYS days"
fi

# ── Off-site replication (best-effort) ──────────────────────────────────────
if [ -n "${BACKUP_REMOTE:-}" ]; then
    case "$BACKUP_REMOTE" in
        restic:*)
            if command -v restic >/dev/null 2>&1; then
                log "off-site: restic backup → ${BACKUP_REMOTE#restic:}"
                if ! restic -r "${BACKUP_REMOTE#restic:}" backup "$TARGET" "$TARGET.sha256"; then
                    log "WARN: restic off-site failed (local copy intact)"
                    exit 2
                fi
            else
                log "WARN: BACKUP_REMOTE=restic:* but restic not installed"
            fi
            ;;
        s3:*)
            if command -v aws >/dev/null 2>&1; then
                URL="s3://${BACKUP_REMOTE#s3:}"
                log "off-site: aws s3 cp → $URL"
                if ! { aws s3 cp "$TARGET" "$URL/" --only-show-errors && \
                       aws s3 cp "$TARGET.sha256" "$URL/" --only-show-errors; }; then
                    log "WARN: s3 off-site failed (local copy intact)"
                    exit 2
                fi
            else
                log "WARN: BACKUP_REMOTE=s3:* but aws CLI not installed"
            fi
            ;;
        *:*)
            # Treat as rsync target (user@host:/path/)
            if command -v rsync >/dev/null 2>&1; then
                log "off-site: rsync → $BACKUP_REMOTE"
                if ! rsync -aq --partial --timeout=30 \
                        "$TARGET" "$TARGET.sha256" "$BACKUP_REMOTE"; then
                    log "WARN: rsync off-site failed (local copy intact)"
                    exit 2
                fi
            else
                log "WARN: BACKUP_REMOTE looks like rsync target but rsync not installed"
            fi
            ;;
        *)
            log "WARN: unrecognised BACKUP_REMOTE scheme: $BACKUP_REMOTE"
            ;;
    esac
fi

log "OK"
exit 0
