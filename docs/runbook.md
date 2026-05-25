# PWDnow — Incident Runbook

Audience: on-call operator. Cross-referenced by the Prometheus alert
annotations (`deploy/prometheus/pwdnow.rules.yml`).

Conventions: every playbook starts with **Symptom**, **Triage** (read-only
commands), then **Mitigate** (the change you make), and ends with
**Verify** (how you know you're done). Never run a "Mitigate" step blind
— always do the triage first.

---

## 0. Top-of-runbook quick reference

```
# Liveness
systemctl status vault-daemon pwdnow-web nginx pwdnow-monitor
journalctl -u vault-daemon -n 50 --no-pager
journalctl -u pwdnow-web   -n 50 --no-pager

# Deep health (localhost only)
curl -s http://127.0.0.1:1234/health?deep=1 | jq

# Backups
ls -lh /var/backups/vault-daemon/ | tail -5
systemctl list-timers | grep vault-daemon

# Reload — never restart unless required
systemctl reload nginx        # uses safe-reload wrapper (G9)
systemctl restart pwdnow-web  # drains 25 s, ~3 s downtime
```

---

## 1. Web tier down (alert: `PWDnowWebDown`)

**Symptom:** Prometheus reports `up{job="pwdnow-web"} == 0`; users see 502.

**Triage:**
```
systemctl status pwdnow-web --no-pager
journalctl -u pwdnow-web -n 100 --no-pager
ss -ltnp | grep :1234
```

Common causes, in order of probability:

| Cause | Tell |
|---|---|
| Port 1234 taken by another process | `ss -ltnp` shows non-Node holder |
| Daemon socket missing | journal shows `daemon socket … not reachable` |
| OOM kill | `dmesg \| grep -i killed` shows the Node process |
| Bad config / env | journal shows uncaught exception at boot |

**Mitigate:**
```
# If it's wedged but the binary is fine:
systemctl restart pwdnow-web

# If it's a config issue, fix the env file, then:
systemctl restart pwdnow-web

# If the host is OOMing, scale memory down first (kills 1 worker):
pm2 scale pwdnow -1     # only if you're on the PM2 path, not systemd path
```

**Verify:** `curl -fsS http://127.0.0.1:1234/health` returns 200 and
`up{job="pwdnow-web"}` recovers within 90 s.

---

## 2. Daemon unreachable (alert: `PWDnowDaemonUnreachable`)

**Symptom:** Web tier is up but every vault operation 503s. WS connections
metric is flat at 0.

**Triage:**
```
systemctl status vault-daemon --no-pager
journalctl -u vault-daemon -n 100 --no-pager
ls -l /run/vault-daemon/vault.sock
sudo -u pwdnow socat - UNIX-CONNECT:/run/vault-daemon/vault.sock < /dev/null  # should connect
```

**Mitigate:**
```
systemctl restart vault-daemon
```

Daemon watchdog (`WatchdogSec=10s`) usually auto-restarts within 30 s of a
hang, so if you find yourself here the auto-recovery already failed; check
for a Restart=on-failure exit-code 42 (FIPS POST failure — escalate, don't
just restart-loop).

**Verify:** `curl -s http://127.0.0.1:1234/health?deep=1 | jq .daemon_ok`
returns `true` and `daemon_latency_ms < 50`.

---

## 3. Error-budget burn (`PWDnowErrorBudgetBurnFast` / `…BurnSlow`)

**Symptom:** Sustained 5xx rate above the 99.9% SLO. You are leaking error
budget; if fast-burn, the monthly budget is gone in ~2 days.

**Triage:**
```
# Top error routes
curl -s http://127.0.0.1:1234/metrics | grep pwdnow_http_request_duration_seconds_count | grep 'status="5'

# Recent web-tier exceptions
journalctl -u pwdnow-web -p err --since=-1h --no-pager
```

**Mitigate:**
- If the cause is a single broken route, roll back the last deploy:
  ```
  git -C /opt/pwdnow log --oneline -5
  cd /opt/pwdnow && git checkout <previous-sha> && systemctl restart pwdnow-web
  ```
- If the cause is the daemon, see §2.
- If the cause is an external dep (HIBP, cert provider), set the affected
  feature to degraded mode rather than fail-closed.

**Verify:** `pwdnow:availability:ratio_5m > 0.999` for 15 min.

---

## 4. Backup failure (alert: from `pwdnow-alert@vault-daemon-backup.service`)

**Symptom:** Webhook fires with `unit=vault-daemon-backup.service host=…
FAILED`. The OnFailure= hook is now wired (G4), so this should never be
silent.

**Triage:**
```
systemctl status vault-daemon-backup.service --no-pager
journalctl -u vault-daemon-backup.service -n 100 --no-pager
df -h /var/backups/vault-daemon
ls -lh /var/backups/vault-daemon/ | tail -5
```

**Mitigate:**
1. Free disk if `disk_free_pct_backup < 8`:
   ```
   find /var/backups/vault-daemon -name 'vault-*.db' -mtime +60 -delete
   find /var/backups/vault-daemon -name 'vault-*.db.sha256' -mtime +60 -delete
   ```
2. If the daemon was writing during backup and locked WAL → run the backup
   manually with the daemon paused:
   ```
   systemctl stop vault-daemon-backup-verify.timer
   /usr/local/sbin/vault-backup.sh
   systemctl start vault-daemon-backup-verify.timer
   ```
3. If `BACKUP_REMOTE` is set and rsync is failing, check SSH key & remote disk.

**Verify:** Next hourly tick succeeds; `backup_age_secs < 7200` in
`/health?deep=1`.

---

## 5. Restore drill failure (alert: from `pwdnow-alert@vault-daemon-restore-drill.service`)

**Symptom:** Weekly drill (Sun 04:00 UTC) reports `DRILL FAIL`. This is the
most important canary in the whole stack — assume your backups are unusable
until proven otherwise.

**Triage:**
```
journalctl -u vault-daemon-restore-drill.service -n 200 --no-pager
ls -lh /var/backups/vault-daemon/ | tail -10
sha256sum -c /var/backups/vault-daemon/vault-*.db.sha256 | tail -10
```

**Mitigate:**
- If a single backup is corrupt, delete *only that backup* and retry the
  drill against the previous one:
  ```
  rm /var/backups/vault-daemon/vault-<ts>.db{,.sha256}
  systemctl start vault-daemon-restore-drill.service
  ```
- If all recent backups fail, the daemon is producing corrupt backups —
  STOP, escalate, do NOT delete anything else. Take a manual `.backup` and
  compare bytes against a known-good prior backup before changing anything.

**Verify:** `journalctl -u vault-daemon-restore-drill.service` shows
`DRILL PASS`.

---

## 6. TLS cert expiring (`tls_cert_days_left_min` low)

**Symptom:** Monitor alert "TLS cert expires in <N> days" (warn ≤14, crit ≤5).

**Triage:**
```
openssl x509 -enddate -noout -in /etc/ssl/vault/cert.pem
openssl x509 -enddate -noout -in /etc/ssl/vault/cert-rsa.pem
```

**Mitigate (Let's Encrypt example):**
```
certbot renew --deploy-hook 'systemctl reload nginx'
```

**Verify:** `openssl x509 -enddate` reports a fresh date and the browser
shows the new cert. Re-run cert collector by sending `SIGHUP` to the monitor.

---

## 7. Auth brute force (`PWDnowAuthFailureSpike`)

**Symptom:** Sustained > 30 failed-auth/min for 5+ min.

**Triage:**
```
# Top failing IPs in the last hour
journalctl -u pwdnow-web --since=-1h --no-pager | grep '/api/auth/login' | grep '" 401' | \
    awk '{print $NF}' | sort | uniq -c | sort -nr | head -10
```

**Mitigate:** Block the top offender at the firewall:
```
sudo nft add element inet filter blacklist { <IP> }
```

The daemon's exponential lockout (`LOCKOUT_SCHEDULE_SECS`) already throttles
the targeted account, so this is about edge-level shedding, not a vault
threat. Don't reset the lockout counter — let it expire naturally.

**Verify:** `rate(pwdnow_auth_attempts_total{result="fail"}[5m]) < 0.1`.

---

## 8. Memory pressure (`PWDnowMemoryHigh`)

**Symptom:** Node RSS > 800 MiB for 10 min. Possible leak in the WS proxy.

**Triage:**
```
curl -s http://127.0.0.1:1234/metrics | grep -E 'process_resident_memory_bytes|pwdnow_ws_connections_active|nodejs_heap_size_used'
```

If WS connection count tracks memory, it's the connection table — restart
will reclaim it. If heap grows independent of WS, there's a real leak —
take a heap snapshot before restarting (`kill -SIGUSR2 $(pidof node)` with
`--inspect`) and file it.

**Mitigate:** `systemctl restart pwdnow-web` (drains 25 s).

**Verify:** RSS returns to baseline (< 300 MiB) within 5 min.

---

## 9. Event-loop lag (`PWDnowEventLoopLag`)

**Symptom:** p99 lag > 250 ms for 5 min. Synchronous CPU work is blocking
the server.

**Triage:** `top -p $(pidof node)` — single-threaded ≈100% CPU.

**Mitigate:** The usual culprit is a long synchronous JSON parse on a
large request body, or a scrypt hash on the auth path. Check whether a
specific endpoint correlates (`/api/auth/login` is the prime suspect; it
uses scryptSync at N=2^17 — *intentional* but CPU-heavy).

If the load is legitimate, scale out (Tier-3 second host). If it's a
single bad route, gate it behind a stricter rate limit in
`deploy/nginx/vault.conf`.

**Verify:** `nodejs_eventloop_lag_p99_seconds < 0.05`.

---

## 10. Full disaster recovery — host wiped

**Symptom:** Host is gone (hardware failure, ransomware, drunken `rm -rf`).

**RTO:** 30 minutes if you have an off-site backup. Hours if you do not.

1. **Provision a new host** with the same OS and CPU arch (Linux x86_64 or
   arm64). Install `deploy/host-hardening.md`.
2. **Restore the daemon DB:**
   ```
   sudo install -d -o vault -g vault -m 0700 /var/lib/vault-daemon
   # If you have off-site:
   restic -r <REPO> restore latest --target /var/lib/vault-daemon --include vault.db
   # Or pull from a known-good off-site copy:
   rsync user@backup-host:/var/backups/vault-daemon/vault-<LATEST>.db /var/lib/vault-daemon/vault.db
   sudo chown vault:vault /var/lib/vault-daemon/vault.db
   sudo chmod 0640 /var/lib/vault-daemon/vault.db
   ```
3. **Restore the `.meta` sidecar** (also part of the backup set; without it
   the daemon cannot read the encrypted VMK).
4. **Reinstall the binary + systemd unit + AppArmor profile + nginx config:**
   ```
   cd /path/to/PWDnow && make install
   ```
5. **Bring up services in order** (daemon → web → nginx):
   ```
   systemctl enable --now vault-daemon
   systemctl enable --now pwdnow-web
   systemctl enable --now pwdnow-monitor
   systemctl reload nginx
   ```
6. **Re-run a restore drill before declaring success:**
   ```
   systemctl start vault-daemon-restore-drill.service
   ```
7. **Verify end-to-end** by logging in with the master password (which the
   user, not the host, holds). If you can unlock, the recovery succeeded.

**Lesson learned check:** if the host failure took > 30 min to recover, the
gap is almost always *unrehearsed off-site restore*. Schedule the next
quarterly DR drill on the calendar before you close the incident.
