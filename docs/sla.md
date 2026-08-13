# PWDnow — SLA 99.99% Architectural Assessment (v2, Deep)

**Author:** Senior Architecture Review
**Date:** 2026-05-16
**Commit audited:** `d7fa58f` (current HEAD on `master`)
**Methodology:** Grounded source review of `daemon/src/main.rs`, `daemon/src/vault/state.rs`, `daemon/src/vault/db.rs`, `daemon/src/ipc/{protocol.rs,socket.rs}`, `daemon/build.rs`, `daemon/Cargo.toml`, `web/server.js`, `web/auth.js`, `web/ecosystem.config.cjs`, `web/playwright.config.ts`, `web/vite.config.ts`, `web/package.json`, `deploy/{vault-daemon.service,pwdnow-monitor.{service,toml},vault-daemon-backup.{service,timer},Dockerfile,Makefile,apparmor.d/vault-daemon,nginx/vault.conf}`, `monitor/Cargo.toml`, `monitor/src/`, `.github/workflows/{ci.yml,release.yml}`, `run_pwdnow.sh`, `setup_autostart.sh`, cross-referenced with `flaws.md` (2026-05-15 red-team audit).
**Reading frame:** the project will soon publish on GitHub for self-host by amd64 and arm64 users; the current dev environment is **macOS M1 + Parallels Desktop Linux VM (aarch64)**. This biases everything in the tree toward aarch64 in ways the author may not have noticed.
**Scoring scale:** 0 % = no SLA · 100 % = 99.99 % (≤ 52 min 36 s downtime / year · ≤ 4 min 23 s / month) achievable end-to-end from browser through Nginx → Express → Unix socket → Rust daemon → SQLCipher DB, **across all supported install targets** (Linux amd64, Linux arm64, macOS, Docker on either arch).

---

## 0. HEADLINE SCORE: **17 / 100**

```
0                                                                    100
├──●──────────────────────────────────────────────────────────────────┤
NONE 17                                                           99.99%
```

```
┌────────────────────────────────────────────────────────────────────────┐
│  Layer-by-layer SLA readiness (revised after deep inspection)          │
│    Cross-platform packaging (amd64 + arm64 + macOS + Docker): 8 / 100 │
│    Build & release pipeline (CI/CD, multi-arch, reproducibility): 25  │
│    Browser ↔ Nginx edge (TLS, rate-limit, caching):           45 / 100│
│    Express app tier (Node, PM2):                              26 / 100│
│    Express ↔ Daemon IPC (Unix socket, WS proxy):              17 / 100│
│    Vault daemon (Rust, watchdog, self-heal):                  42 / 100│
│    Storage (SQLCipher, sidecar, backup, R2 sync):             19 / 100│
│    Observability + auto-remediation (pwdnow-monitor):         55 / 100│
│    Deploy topology (single host, no HA, no DR):                5 / 100│
│    Weighted total:                                            17 / 100│
│                                                                        │
│  WHY LOWER THAN v1 (24 → 17)                                          │
│    Two unfair penalties from v1 are removed (+5):                     │
│      • C-01 is in fact FIXED at auth.js:1004 ('const mfaCfg =         │
│        readUserBlob(u.id, 'mfa_config', {})') — flaws.md was stale.   │
│      • AppArmor uses @{multiarch}; not hardcoded to aarch64.          │
│                                                                        │
│    Nine new genuine penalties surface on deeper inspection (−12):     │
│      1. daemon/build.rs:7 hardcodes /usr/lib/aarch64-linux-gnu        │
│         → daemon WILL NOT BUILD on amd64. Half the GitHub audience    │
│         can't install PWDnow at all. SLA = 0 for them.                │
│      2. build.rs:16 hardcodes LIBCLANG_PATH=/usr/lib/llvm-21/lib —    │
│         most distros ship llvm-14/17. bindgen build fails.            │
│      3. build.rs:23 hardcodes /usr/include/fido.h — wrong on macOS    │
│         (/opt/homebrew/include) and Alpine (musl layout).             │
│      4. CI workflow runs every test/lint/audit with '|| true'         │
│         (.github/workflows/ci.yml:28,30,56) → CI is GREEN ALWAYS.     │
│         Regressions land silently. SLA cannot be defended through     │
│         a pipeline that mathematically cannot fail.                   │
│      5. Release workflow runs ONLY on ubuntu-latest (amd64). No       │
│         buildx, no matrix, no arm64 artifact. ARM users build from    │
│         source, hit (1)-(3) above, are stuck.                         │
│      6. Hourly backup is 'cp vault.db' but DB runs in journal_mode=   │
│         WAL (db.rs:43). 'cp' captures the file at a checkpoint        │
│         boundary AND OMITS vault.db-wal + vault.db-shm — restored     │
│         backup loses every write since the last checkpoint. Untested  │
│         restores fail silently. RPO claim of "1 hour" is fiction.     │
│      7. synchronous=NORMAL (db.rs:44) — committed writes can be       │
│         lost on power loss. Combined with (6) = real RPO is "last    │
│         clean checkpoint", indeterminate. Need synchronous=FULL.      │
│      8. setup_autostart.sh:22 runs the daemon UNDER PM2 instead of    │
│         systemd. This destroys CAP_IPC_LOCK (VMK can swap to disk),  │
│         MemorySwapMax=0, AppArmor, PrivateTmp, watchdog, sd_notify.   │
│         A single deploy via this script regresses every hardening    │
│         primitive at once.                                            │
│      9. Per-(uid, conn_id) lockout (state.rs:200) is bypassable by    │
│         simply opening a new WebSocket — each new conn_id starts the  │
│         counter at zero. The "lockout" is essentially a no-op against │
│         any attacker who can dial the WS endpoint.                    │
│                                                                        │
│    Net change: +5 (corrections) − 12 (new finds) = −7 → 17/100.       │
│                                                                        │
│  WHAT STAYS GOOD                                                       │
│    • SQLCipher integrity-check on every open (db.rs:30-38).           │
│    • Multi-slot, TTL'd challenge map (state.rs:106, M-01 fix is real).│
│    • Tokio watchdog correctly wired (main.rs:62-77).                  │
│    • pwdnow-monitor is genuinely SRE-grade.                           │
│    • CI does pin Node via .nvmrc=20.14.0 + 'npm ci --strict-peer-deps'│
│    • Release workflow emits CycloneDX SBOM, SLSA provenance, cosign — │
│      genuinely strong supply-chain story (single-arch, but signed).   │
│    • Per-request CSP nonce, SRI cache, mtime invalidation in server.js│
│    • Per-request X-Request-ID for trace correlation.                  │
│                                                                        │
│  PATH TO 100 — §10 phased roadmap; ~6 months focused engineering.     │
└────────────────────────────────────────────────────────────────────────┘
```

### Corrections to the v1 assessment

| v1 claim | Reality on disk | Impact |
|---|---|---|
| "C-01 `mfaCfg` ReferenceError crashes every server-mode login" | Already fixed at `web/auth.js:1004` — `const mfaCfg = readUserBlob(u.id, 'mfa_config', {});`. flaws.md is stale. | +4 pts |

### Corrections to *this* (v2) assessment (added 2026-07-28)

This document's own citations against `web/auth.js:NNN` are now stale too — `auth.js` has since been split into `routes/auth/*.js` + `lib/*.js` (current `auth.js` is a 98-line init/mount shim; e.g. `mfaCfg` now lives at `routes/auth/login.js:234`, not `auth.js:1004`). More importantly, most of the "Nine new genuine penalties" in the headline box above have themselves been fixed since 2026-05-16 and should not be treated as current:

| v2 claim (headline box, items 1-9) | Reality on disk (verified 2026-07-28) | Status |
|---|---|---|
| 1-3. `build.rs` hardcodes `/usr/lib/aarch64-linux-gnu`, `LIBCLANG_PATH=/usr/lib/llvm-21/lib`, `/usr/include/fido.h` | `daemon/build.rs` calls `pkg_config::probe_library` first for every native dep, with cross-platform fallback scanning (Debian/RHEL/macOS Homebrew paths) only when pkg-config is unavailable; `find_libclang_path()`/`find_fido_header()` search `llvm-config`/`clang`/multiple llvm-14..21 + Homebrew paths, not one hardcoded path. | **Fixed** — the "daemon WILL NOT BUILD on amd64" claim no longer holds. |
| 4. CI runs test/lint/audit with `\|\| true` — "CI is GREEN ALWAYS" | `.github/workflows/ci.yml` — only the `Lint` step (line 28) has `\|\| true`. `Test` (`npm run test`, `cargo test`), `npm audit --audit-level=high`, and `cargo audit --deny warnings` all run unguarded and can fail the build. | **Stale** — CI can and does fail on test/audit regressions today. |
| 5. Release workflow runs only on `ubuntu-latest` (amd64), no matrix | `.github/workflows/release.yml` has `strategy.matrix` over `ubuntu-latest` (amd64), `ubuntu-24.04-arm64`, and `macos-14`. | **Fixed** — three-platform release matrix already exists. |
| 7. `synchronous=NORMAL` risks lost commits on power loss | `daemon/src/vault/db.rs:60` sets `conn.pragma_update(None, "synchronous", "FULL")`. | **Fixed.** |
| 8. `setup_autostart.sh` runs the daemon under PM2, destroying systemd hardening | `setup_autostart.sh` no longer exists in the repo. | **Moot** — re-verify against whatever the current autostart path is before re-flagging. |
| 9. Per-`(uid, conn_id)` lockout bypassable by opening a new WebSocket (fresh `conn_id` resets the counter) | `daemon/src/vault/lockout.rs`'s `LockoutTracker` keys **only** on `uid` (`HashMap<u32, (u32, Instant)>`); `conn_id` is threaded through every call site but never read by the tracker. So the described bypass mechanism is backwards — the lockout isn't keyed on `conn_id` at all (in this single-tenant daemon `uid` is hardcoded to `1000`, so this is currently a global-per-installation lockout, not a per-connection one). | **Mischaracterized** — real issue is dead `conn_id` plumbing (tracked separately), not a `conn_id`-reset bypass. |
| 6. Hourly backup `cp`s `vault.db` only, misses `-wal`/`-shm` under `journal_mode=WAL` | `deploy/vault-daemon-backup.service` still does a bare `cp .../vault.db ...` with no `-wal`/`-shm` handling. | **Still valid** — not re-verified as fixed. |

Six of the nine "genuine new penalties" behind the −12 in the headline box are now fixed, moot, or mischaracterized; only #6 was confirmed still open. The 17/100 headline score should be recomputed before being relied on — this note corrects the record, it does not re-run the scoring formula.

### Scoring formula (revised)

```
Floor (no SLA)                                                          0
+ Watchdog + monitor self-healing within single host                  +12
+ Tokio watchdog wired correctly + sd_notify integration               +4
+ Health endpoint is true end-to-end (Unix socket connect probe)       +4
+ Hourly encrypted backup timer exists (BUT WAL bug — see §5.5)        +1
+ Atomic sidecar writes (state.rs:348 — tmp + fsync_all + rename)      +3
+ FIPS POST gate + RestartForceExitStatus=42 (no crash loop on POST)   +2
+ Multi-slot challenge store with TTL (M-01 fix, state.rs:106-144)     +2
+ Per-conn lockout (better than v1 global, still bypassable, +1 net)   +1
+ SQLCipher cipher_integrity_check on every open (db.rs:30-38)         +2
+ Per-(uid+conn_id) audit chain & pending audit batching               +1
+ Nginx TLS 1.3 only, CNSA 2.0 ciphers, OCSP stapling                  +2
+ Release pipeline: SBOM (CycloneDX) + SLSA provenance + cosign         +3
+ Per-request CSP nonce + SRI cache + mtime-aware invalidation         +2

− daemon/build.rs:7 hardcoded /usr/lib/aarch64-linux-gnu               −5
− build.rs:16 hardcoded LIBCLANG_PATH=/usr/lib/llvm-21/lib             −2
− build.rs:23 hardcoded /usr/include/fido.h                            −1
− .github/workflows/ci.yml runs every check with '|| true'             −3
− Release workflow single-arch (ubuntu-latest); no buildx matrix       −3
− Hourly backup = 'cp vault.db' on a WAL database (loses wal/shm)      −2
− synchronous=NORMAL in WAL mode (writes can be lost on power loss)    −1
− setup_autostart.sh runs daemon under PM2 (loses every sandbox prim)  −3
− Per-(uid, conn_id) lockout bypassable by new WS connection           −1
− Three different socket paths in tree (state drift across modes)      −1
− Express PORT defaults to 3000 (server.js:23) vs 1234 elsewhere       −1
− No graceful drain on Express SIGTERM; PM2 kill_timeout not set       −1
− PM2 instances:1 / exec_mode:fork (deploys = downtime)                −2
− No upstream pool in Nginx; one backend hardcoded                     −1
− No SQLite '.backup' API in backup script (no quiescence)             −1
− WS FIFO single-in-flight per tab; timeout tears down whole WS        −2
− Synchronous fs ops in auth.js (15 writeFileSync/readFileSync calls)  −1

Subtotal                                                                17
Final score                                                       17/100
```

Achieving 99.99 % is impossible on the current architecture. **A realistic single-host ceiling with every fix applied is ~99.5 % (≈ 43 h/year downtime).** The remaining decade gap requires topology change (see §10).

---

## 1. What 99.99 % actually means

| Window | Allowed downtime |
|---|---|
| Per year | **52 min 36 s** |
| Per quarter | 13 min 9 s |
| Per month | **4 min 23 s** |
| Per week | 1 min 1 s |
| Per day | 8.6 s |

Inclusive of: planned deploys, dependency upgrades, certificate rotation, `pm2 reload`, nginx reload, daemon panics, OOM kills, FIPS POST failures, disk-full events, network flaps, BGP withdrawals, kernel patches, fs corruption, SQLite migrations, cosmic-ray bit-flips, and **every release that someone in the wild can't run** because their architecture isn't supported (a release that fails to install on amd64 is a 100 % outage to the user who tried it).

A single 6-minute SQLite migration in production blows the monthly budget. A single afternoon spent restoring from `vault-*.db` blows the yearly budget five times over. A single x86 user filing "I can't build" on GitHub during release week blows it for that user permanently.

99.99 % is incompatible with: any single failure domain, any single-process state store, any non-atomic deploy, any unscripted manual recovery step, any backup with RPO > 1 minute on the critical path, **any release pipeline that does not produce binaries for all supported platforms automatically**.

---

## 2. End-to-end request topology (today, single host)

```
                  ┌───────────────────────────────────────────┐
                  │  Browser (React 19 SPA)                   │
                  │  - WebSocket /ws (msgpack length-prefixed)│
                  │  - REST /api/*  (JWE _pwd_sess cookie)    │
                  │  - SecureKeyStore (in-tab JS private)     │
                  └────────────────────┬──────────────────────┘
                                       │ HTTPS (TLS 1.3, CNSA 2.0)
                                       ▼
                  ┌───────────────────────────────────────────┐
                  │  Nginx (single host, no upstream pool)    │
                  │  - Terminates TLS, rate-limit zones      │
                  │  - Proxies / and /ws to 127.0.0.1:1234   │
                  │  - SPOF: one nginx, one cert, one IP     │
                  └────────────────────┬──────────────────────┘
                                       │ HTTP 1.1 keep-alive
                                       ▼
        ┌──────────────────────────────────────────────────────────┐
        │  Express (Node 20.14.0) — PM2 fork mode, instances:1     │
        │  ecosystem.config.cjs:11  ← SPOF #1                      │
        │  In-memory: SETUP_TOKEN, wsConnectCounts,               │
        │   wsNonceCounts, activeWsCount, SRI cache,              │
        │   activeJwtJtis, failed-login lockout                   │
        │  15 × sync fs ops in auth.js — event loop blockers       │
        │  PORT default 3000 in code, 1234 in pm2 — split-brain    │
        └────────────────────┬─────────────────────────────────────┘
                             │ AF_UNIX  /run/vault-daemon/vault.sock   ← systemd path
                             │      OR  /tmp/vault-daemon-run/...      ← pm2 path
                             │      OR  /tmp/vault-dev.sock            ← run script path
                             ▼  (three sources of truth)
        ┌──────────────────────────────────────────────────────────┐
        │  vault-daemon (Rust 1.80, Tokio, single process)         │
        │  vault-daemon.service: Restart=on-failure,              │
        │    RestartSec=5s, WatchdogSec=30s  ← SPOF #2            │
        │  daemon/build.rs HARDCODES aarch64 paths → amd64 won't  │
        │  build at all                                            │
        │  setup_autostart.sh demotes daemon to PM2 → loses        │
        │   CAP_IPC_LOCK, MemorySwapMax=0, sandbox, watchdog      │
        │  Per-(uid, conn_id) lockout bypassable by reconnect      │
        └────────────────────┬─────────────────────────────────────┘
                             │ SQLCipher (XChaCha20-Poly1305 via libsqlcipher)
                             │ journal_mode=WAL, synchronous=NORMAL
                             ▼
        ┌──────────────────────────────────────────────────────────┐
        │  vault.db + vault.db-wal + vault.db-shm + vault.db.meta  │
        │   ← SPOF #3 (single file, single disk, single host)     │
        │  Backup: hourly 'cp vault.db' → MISSING WAL/SHM         │
        │   → restored backup = last checkpoint, RPO indeterminate │
        │  Sync: cloudflare.rs exists but NO IPC handler — dead   │
        └──────────────────────────────────────────────────────────┘
```

Every box is a SPOF. Every disk is a SPOF. Every restart of any process is user-visible (WS drops, re-unlock UX). The release pipeline produces artifacts for only one of the four target platforms.

---

## 3. Cross-platform deployment matrix (new in v2)

The user has confirmed PWDnow will go to GitHub with both amd64 and arm64 audiences. The repo's current state vs each realistic install target:

| Install target | Daemon build | Web build | Process supervisor | Sandbox | Status |
|---|---|---|---|---|---|
| **Linux amd64 (Ubuntu/Debian)** | **FAILS** — `build.rs:7` hardcodes `/usr/lib/aarch64-linux-gnu`; `build.rs:16` hardcodes `/usr/lib/llvm-21/lib` | OK | systemd unit shipped | AppArmor (`@{multiarch}` ok) | 🔴 **Build fails out of the box** |
| **Linux arm64 (Ubuntu/Debian on Pi 5, Graviton, Parallels VM)** | OK (current dev env) | OK | systemd unit shipped | AppArmor (`@{multiarch}` ok) | 🟡 **Works only on this exact env** |
| **Linux amd64 (RHEL/Fedora/Rocky)** | FAILS (build.rs paths) + libfido2 from different package name | OK | systemd unit shipped | **No AppArmor — SELinux instead, no profile shipped** | 🔴 |
| **Linux arm64 (RHEL family)** | Path-fragile + no SELinux profile | OK | systemd | none | 🔴 |
| **Linux amd64 (Alpine)** | FAILS — musl vs glibc, no libsqlcipher in default repos, no llvm-21 | Node-musl needed | **No systemd — OpenRC/dinit** | none | 🔴 |
| **macOS arm64 native** | FAILS — `/usr/include/fido.h` absent, libsodium at `/opt/homebrew/include` | OK | **No systemd — launchd .plist needed (not shipped)** | none | 🔴 |
| **macOS x64 native** | Same as above | OK | launchd | none | 🔴 |
| **Windows + WSL2** | Same as Linux of host distro; cert paths differ; older WSL2 has no systemd | OK | systemd (WSL2 ≥ 0.67) | none | 🟡 |
| **Docker amd64** | Possible if cross-compiled; current Dockerfile uses native `cargo build --release` on the build platform → only builds for the host arch | OK | **PID 1 is daemon — no restart, no watchdog, no monitor** | inherits Linux of host | 🟡 |
| **Docker arm64** | Same — no `--platform`, no buildx matrix | OK | as above | as above | 🟡 |
| **Docker multi-arch (manifest list)** | **Not shipped** | n/a | n/a | n/a | 🔴 |

**Bottom line:** As of `d7fa58f`, **exactly one platform builds and runs cleanly: Linux arm64 Ubuntu/Debian with libllvm-21 installed.** That happens to be the dev environment (Mac M1 → Parallels → Ubuntu). Every GitHub install attempt outside that exact stack will hit a hard error in the first 60 seconds.

For a 99.99 % SLA across the audience this repo is about to face, the cross-platform story is the dominant risk — it precedes every other SLA concern, because a user who can't install has 100 % downtime.

### What needs to change to ship cleanly

1. **`daemon/build.rs` must be re-arch-aware.** Replace:
   ```rust
   println!("cargo:rustc-link-search=native=/usr/lib/aarch64-linux-gnu");
   println!("cargo:rustc-env=LIBCLANG_PATH=/usr/lib/llvm-21/lib");
   ```
   with `pkg-config`-driven discovery for `libsodium`, `libsqlcipher`, `libfido2`, `liboqs`, and `llvm-config --libdir` (or `clang -print-search-dirs`) for `LIBCLANG_PATH`. The bindgen include needs `pkg-config --cflags fido2`, not a literal `/usr/include/fido.h`.
2. **Vendor the C deps where reasonable.** `libsodium-sys` already has a `bundled` feature; switch to it to eliminate the runtime DSO dependency entirely. `rusqlite` has `bundled-sqlcipher` likewise. `libfido2` is harder to vendor — document the install command per OS.
3. **Add `rust-toolchain.toml`** pinning the exact rustc version so cross-compilation is reproducible. (CI today uses `dtolnay/rust-toolchain@stable` which floats.)
4. **Multi-arch CI matrix.** Build & test on `ubuntu-latest` (amd64), `ubuntu-22.04-arm64` (free for public repos), and at least one `macos-14` (arm64) job for the daemon. Fail the workflow on any matrix leg failure.
5. **Multi-arch release.** Use `actions-rs/cross` or `cargo-zigbuild` to produce both `vault-daemon-linux-amd64`, `vault-daemon-linux-arm64`, and `vault-daemon-macos-universal`. Sign each blob with cosign. Build a `Dockerfile` with `--platform=$BUILDPLATFORM` and `docker buildx build --platform linux/amd64,linux/arm64` and push a manifest list.
6. **Ship a macOS `LaunchDaemon` plist** alongside `vault-daemon.service` so non-systemd users have a supervisor with `KeepAlive`, `ExitTimeOut`, and `StandardOutPath`.
7. **Ship an OpenRC init script** for Alpine / Gentoo / Devuan users (the security-conscious crowd most likely to want PWDnow).
8. **Per-distro install docs** — `INSTALL.md` per OS with the apt/dnf/apk/brew commands; the README must direct the user there before they run `cargo build`.

---

## 4. Single Points of Failure (SPOFs, updated)

| # | SPOF | File / config | Failure mode | MTTR (current) | SLA impact |
|---|---|---|---|---|---|
| 1 | Single Express process | `web/ecosystem.config.cjs:11` (`instances:1, exec_mode:'fork'`) | OOM, panic, deploy, pm2 restart | 3–8 s + WS reconnect storms | **Blocks 99.99 %** |
| 2 | Single vault daemon | `deploy/vault-daemon.service` | Panic, watchdog kill, FIPS POST exit-42 | 5–35 s (RestartSec+POST+bind) | **Blocks 99.99 %** |
| 3 | Single SQLCipher file | `daemon_data/vault.db` (+ `-wal`/`-shm`) | Disk failure, fs corruption | **Hours** (find backup, manually replay WAL if you still have it) | **Blocks 99.99 %** |
| 4 | Single host | All services co-located | Power, kernel, NIC, BMC, hypervisor | Hours to days | **Blocks 99.99 %** |
| 5 | Single Nginx | `nginx/vault.conf` proxies to one backend | Config reload error, OOM, port collision | Manual + monitor restart | Caps SLA |
| 6 | Single Unix socket | one of 3 hardcoded paths | Stale socket post-crash, perms drift | Daemon must rebind | Compounds SPOF #2 |
| 7 | In-process Express state | rate-limit maps, SETUP_TOKEN, ws maps, SRI cache, JWE JTI list, lockout map | Every restart wipes all | Lost cross-restart state | Caps deploy SLO |
| 8 | In-process daemon state | challenge map, lockout map, VMK, sessions | Every restart drops in-flight unlocks | Re-unlock UX | Caps deploy SLO |
| 9 | WS positional FIFO queue | `daemonClient.ts` — one in-flight; timeout = full WS teardown | One slow op → all-stop → reconnect storm | Browser retry | Cascading failures |
| 10 | No upstream pool in Nginx | `nginx/vault.conf:135-139` | Cannot fail over | N/A | Caps SLA |
| 11 | Backup local-only and **not WAL-aware** | `deploy/vault-daemon-backup.service` `cp vault.db` | Disk loss = backup loss; restore = last checkpoint only | N/A | **RPO indeterminate** |
| 12 | Per-(uid, conn_id) lockout | `daemon/src/vault/state.rs:200-214` | Attacker bypasses by new WS conn | N/A | DoS by design |
| 13 | Build pipeline single-arch | `.github/workflows/release.yml` (no matrix) | amd64 audience gets no binary | Build from source → fails (SPOF #14) | 100 % outage for half audience |
| 14 | Build script hardcoded to aarch64 | `daemon/build.rs:7,16,23` | amd64 build fails | Manual edit per user | 100 % install failure |
| 15 | CI runs every check with `|| true` | `.github/workflows/ci.yml:28,30,56` | Regressions land green | Manual triage post-release | Each release is roulette |
| 16 | `setup_autostart.sh` demotes daemon to PM2 | `setup_autostart.sh:22` | Loses CAP_IPC_LOCK, MemorySwapMax, watchdog, sandbox | Silent — user thinks it's running normally | Security + SLA regression in one command |
| 17 | `synchronous=NORMAL` in WAL mode | `daemon/src/vault/db.rs:44` | Power-loss can lose committed writes | Hours of manual reconstruction | RPO not 0 |
| 18 | Schema migrations not transactional across steps | `daemon/src/vault/db.rs:70-85` | Mid-migration crash → partial schema | Manual fix per-user | Catastrophic on major upgrade |

---

## 5. Layer-by-layer scoring (deepened)

### 5.1 Cross-platform packaging — **8 / 100** (new in v2)
**Strengths:**
- Release workflow signs every artifact with cosign + SLSA provenance.
- Node version pinned in `.nvmrc` = 20.14.0.
- AppArmor profile uses `@{multiarch}` correctly.

**Gaps (these dominate the score):**
- `daemon/build.rs` is the single biggest portability bug in the tree (see §3).
- No `rust-toolchain.toml` — rustc version floats with `dtolnay/rust-toolchain@stable`.
- No multi-arch container image.
- No macOS launchd plist.
- No Alpine/OpenRC init script.
- `Dockerfile` builds with `cargo build --release` — works for whichever arch the runner happens to be (amd64 on `ubuntu-latest`). No `--platform=$TARGETPLATFORM`.
- `setup_autostart.sh` is Linux/PM2-specific and silently breaks security guarantees.
- `run_pwdnow.sh` uses `pkill -9 -f server.js` and `pkill -9 -f "node --expose-gc"` — kills any other `node` process running for the user.

### 5.2 Build & release pipeline — **25 / 100** (new in v2)
**Strengths:** SBOM + provenance + cosign + `SOURCE_DATE_EPOCH=1714521600` for reproducibility intent.
**Gaps:**
- `.github/workflows/ci.yml:28,30,56`: lint, test, and audit all suffixed with `|| true`. The CI **cannot fail**. This is the single biggest pipeline-level SLA bug — every regression lands green.
- `ci.yml` does not run E2E (Playwright). Playwright hardcodes `/usr/bin/brave-browser` which is not on the runner image → would need a setup step. As written, the E2E "gold standard" regression gate is not actually a gate.
- `release.yml` is single-OS, single-arch (ubuntu-latest = amd64).
- `release.yml` lacks an artefact verification step — there's no "download the tarball, untar, run the smoke test on a clean runner" job to catch packaging regressions.
- No vulnerability scan on the final container image (Trivy/Grype) before publish.
- No version-skew check between web/package.json `version` and daemon/Cargo.toml `version` (both are `0.0.0` / `0.1.0` — release tags will be ambiguous).
- `cargo-audit` uses `-D warnings || true` — both flags cancel out (`-D warnings` makes any advisory fatal; `|| true` then ignores it).

### 5.3 Browser ↔ Nginx edge — **45 / 100**
**Strengths:** TLS 1.3 only, CNSA 2.0 cipher (`TLS_AES_256_GCM_SHA384`), CNSA 2.0 group (`secp384r1mlkem1024`), OCSP stapling, HSTS preload, rate-limit zones (`auth_limit`, `general_limit`), gzip excluded from `/api/`, immutable cache on `/assets/`, server-tokens off.
**Gaps:**
- One nginx process, one upstream backend, no `upstream { ... }` block, no active health checks.
- No `proxy_next_upstream` because there's no fallback to next-upstream.
- OCSP resolver hardcoded to `1.1.1.1 8.8.8.8` — external dependency. If both fail, OCSP stapling stalls TLS handshakes.
- No `limit_conn_zone` per IP for WS upgrades at the edge (only inside Express).
- No per-host certificate provisioning automation (Certbot or DNS-01) shipped.
- No HSTS preload submission checklist.
- Single hardcoded `server_name vault.local` — operators have to edit the file in place per deployment.

### 5.4 Express app tier — **26 / 100**
**Strengths:** Helmet CSP with per-request nonce, SRI cache with mtime invalidation, request-id, no-store on `/api/`, JSON body cap 512 KB, WS frame cap 4 MiB, origin check on `/ws`, tab-nonce rate-limit, global WS cap, handshake timeout, trust proxy = loopback.
**Gaps:**
- `instances:1, exec_mode:'fork'` — SPOF #1. The reason it's pinned (in-process state) is honest but blocks SLA.
- `auth.js` uses **15 synchronous file ops** (`writeFileSync`, `readFileSync`, `renameSync`). Under concurrent load, each blocks the single event loop. A 50 ms fs latency × 15 = 750 ms event-loop hang during a busy window. This will surface as `/health` latency spikes.
- `/health` (`server.js:388`) opens a fresh socket on every probe and uses 3 s timeout. A wedged daemon + flood of probes consumes daemon-side fds (cap `LimitNOFILE=4096`).
- No graceful shutdown hook on `SIGTERM`. PM2 hard-kills after `kill_timeout: 1600` ms (default, not overridden). Any WS in mid-frame gets RST.
- No `wait_ready: true` in PM2 config — restarted worker is considered "ready" before HTTP listener binds, race window where Nginx gets 502.
- `max_memory_restart: '1G'` — hard restart with zero warning; no soft-trigger to `pm2 reload` instead of hard restart.
- `MAX_GLOBAL_WS_CONNECTIONS = 200` is a single shared counter — hitting 200 = blanket 1013 close for everyone.
- `WS_NONCE_LIMIT = 200` and `WS_CONNECT_LIMIT = 30` are not configurable.
- PORT default `3000` (`server.js:23`) split-brain with `1234` everywhere else.

### 5.5 Express ↔ Daemon IPC — **17 / 100**
**Strengths:** `SO_PEERCRED` UID auth, length-prefixed msgpack frames, multi-slot challenge map (`state.rs:106`, TTL 600 s, capped at 1000), per-(uid, conn_id) audit/lockout.
**Gaps:**
- FIFO single-in-flight per WS — slow op blocks all subsequent on that tab.
- On timeout, the entire WS is torn down (positional response matching).
- No request multiplexing (would need a request-id field in msgpack frames).
- Unix socket is single-host. Cannot proxy across two Express hosts without a different transport.
- No connection pool — one Unix socket fd per WS. With 200-WS cap × 1 fd each, daemon stays under `LimitNOFILE=4096` but is fragile to increases.
- No reconnect logic in `server.js` daemon socket — on transient `ECONNREFUSED` during daemon restart, WS gets 1011 immediately; browser retries on its own.
- No circuit breaker between Express and daemon.
- **Per-conn lockout is bypassable** by simply opening a new WebSocket — each `conn_id = CONN_COUNTER.fetch_add(1, Ordering::Relaxed)` (`socket.rs:80`) is unique. Anti-brute-force is effectively no-op against a remote attacker.
- Three different socket paths in the tree (`/run/vault-daemon/vault.sock`, `/tmp/vault-daemon-run/vault.sock`, `/tmp/vault-dev.sock`).

### 5.6 Vault daemon — **42 / 100**
**Strengths:** systemd `Type=notify`, watchdog wired into Tokio (main.rs:62-77), `Restart=on-failure`, `RestartForceExitStatus=42` for FIPS POST failures (correct — POST fail = unrecoverable), `MemorySwapMax=0`, `CAP_IPC_LOCK`, hardened sandbox, atomic sidecar writes (state.rs:348 — `tmp + sync_all + rename`), SQLCipher integrity check on every open, multi-slot challenges with TTL.
**Gaps:**
- Single process.
- Single SQLCipher file.
- Restart = full state loss (challenges, sessions, in-flight unlocks).
- Watchdog 30 s → best-case 35 s outage per crash. FIPS POST runtime is in the critical path of every restart.
- No state snapshot on `SIGTERM`. Could fsync a "shutting down cleanly" marker so the next start can skip extra POST passes.
- Schema migrations are sequential `execute_batch` calls (db.rs:70-85). If power dies between `v1` and `v2`, the next open finds an inconsistent schema. Migrations should run in a single outer `BEGIN IMMEDIATE; ... COMMIT` so they're atomic across all version jumps.
- `synchronous=NORMAL` (db.rs:44) — power-loss can lose committed writes; for password-vault semantics, `synchronous=FULL` is correct.
- `journal_mode=WAL` is fine for performance but **the backup script is unaware**: `cp vault.db` does not capture `vault.db-wal` and `vault.db-shm`, so restore drops anything written since the last `wal_checkpoint`. Need `sqlite3 source.db ".backup target.db"` which uses SQLite's online backup API and captures consistent state.
- No periodic `cipher_integrity_check` — only at open. A long-running daemon with silent corruption goes undetected until next restart.
- No periodic `wal_checkpoint(TRUNCATE)` — WAL can grow unbounded between checkpoints.

### 5.7 Storage / backup / sync — **19 / 100**
- WAL backup bug (above) is the dominant penalty.
- No checksum + verify pass after backup.
- No offsite copy.
- `find ... -mtime +30 -delete` retention is naïve — no GFS rotation (daily/weekly/monthly).
- Cloudflare R2 sync code (`daemon/src/sync/cloudflare.rs`) is well-designed (BLAKE3 + zstd + `.conflict` file) but **never wired into IPC**. `grep "SyncNow" daemon/src/ipc/protocol.rs` → 0 hits. Latent code = false promise. Either wire it up with `Request::SyncNow` + a scheduler or delete the file (dead code is a maintenance trap).
- No automated restore drill — backups are never proven by re-opening with the last-known-good password and reading N rows.
- Hourly RPO blows the monthly SLA by an order of magnitude.

### 5.8 Observability + self-healing — **55 / 100**
**Strengths:** `pwdnow-monitor` is the strongest single piece of SLA infrastructure in the tree. 10 s polling, separate WARN/CRIT thresholds, capped exp backoff (5→10→20→40→80 s, max 5), crash-loop detection (3 in 5 min), auto-prune at 92 % disk, notify-send + webhook hooks, cooldown 300 s. `panic = "abort"` in `monitor/Cargo.toml` means a panicked monitor crashes cleanly and systemd respawns it.
**Gaps:**
- Monitor is a SPOF; `WatchdogSec=60s` = 60 s blind window if monitor wedges.
- No metrics export (no Prometheus `/metrics`).
- No structured tracing (no OpenTelemetry).
- `/health` returns JSON, not Prometheus format.
- No external uptime monitor referenced.
- `min_severity = "critical"` → SREs only hear about CRITs (when it's already an outage); burn-rate alerts on CRIT are too late.
- No SLO definitions in code or config; SLA cannot be tracked.

### 5.9 Deploy topology — **5 / 100**
- One host. One of everything.
- No DR site, no documented failover.
- No infrastructure-as-code (no Terraform/Ansible/Pulumi recipes).
- No runbook for the top-10 incident classes.
- No on-call rotation referenced.
- No status page.

---

## 6. SLI / SLO catalog (new — needed to measure SLA before improving it)

PWDnow does not currently define SLIs. To run a 99.99 % SLO you need explicit, measurable indicators and budgets. Proposed minimum set:

| # | SLI | Type | Measurement source | SLO target | Burn-rate alert |
|---|---|---|---|---|---|
| 1 | `/health` returns 200 with `daemon_ok=true` | Availability | External synthetic probe every 30 s from ≥ 2 regions | 99.99 % monthly | 2 % budget in 1 h → page |
| 2 | WS connection succeeds and exchanges first frame within 2 s | Availability | Synthetic probe (login flow, no unlock) | 99.95 % | 5 % budget in 1 h → page |
| 3 | `/api/auth/login` p99 latency | Latency | Server access log | < 1.5 s | 10 % budget in 6 h → warn |
| 4 | Daemon unlock IPC p99 latency | Latency | `pwdnow-monitor` time series | < 800 ms | 10 % budget in 6 h → warn |
| 5 | Daemon restart count per day | Stability | systemd journal `_SYSTEMD_INVOCATION_ID` | ≤ 1 per day | ≥ 3 → page |
| 6 | Backup success + integrity-check pass | Durability | `vault-daemon-backup.service` exit code + verify cron | 100 % over 7-day window | 1 fail → page |
| 7 | Restore drill RTO (monthly synthetic) | Disaster recovery | Cron job that restores last backup to isolated path, opens, reads | ≤ 60 s | 1 fail → page |
| 8 | TLS certificate expiry | Hygiene | Probe certificate from external monitor | ≥ 30 days remaining | ≤ 14 days → warn, ≤ 7 days → page |
| 9 | Cross-arch build success | Packaging | CI matrix on PR + nightly | 100 % | 1 fail blocks merge |
| 10 | Released artifact installs cleanly on a fresh VM per supported OS | Packaging | Nightly smoke test from release tarball | 100 % | 1 fail → page |
| 11 | Disk usage on vault path | Capacity | `pwdnow-monitor` | < 75 % | ≥ 85 % → warn, ≥ 92 % → page (auto-prune triggers) |
| 12 | RSS memory of Express / daemon | Capacity | `pwdnow-monitor` | < 700 MiB / < 1.5 GiB | breach → warn |
| 13 | npm/cargo audit clean | Supply chain | CI on each PR + daily cron | 0 high-severity | 1 high → block merge, alert |
| 14 | Session token revocation propagation | Correctness | Logout test on synthetic | ≤ 1 s | breach → warn |
| 15 | Postgres point read (`users` by `id`/`email_hmac`, `vault_items` by `(user_id, name)`) — indexed single-row lookup, `findUserById`/`findUserByEmailHash`/`getResource` | Latency | `pg` pool query timer, per-query-shape histogram | p50 < 5 ms · p99 < 30 ms | 10 % budget in 6 h → warn |
| 16 | Postgres write (`vault_items` upsert via `setResource`; `users` insert via `insertUser`) | Latency | `pg` pool query timer | p50 < 10 ms · p99 < 50 ms | 10 % budget in 6 h → warn |
| 17 | Postgres row-locked read-modify-write (`updateUserById` — `SELECT ... FOR UPDATE` + `UPDATE` in one tx) | Latency | `pg` pool query timer | p50 < 12 ms · p99 < 60 ms | 10 % budget in 6 h → warn |
| 18 | Postgres pool saturation (active connections / `PG_POOL_MAX`) | Capacity | `pg` pool stats | < 70 % | ≥ 85 % → warn, ≥ 95 % → page |
| 19 | Postgres transport encryption | Security | `web/lib/db/pool.js` TLS config (`PG_TLS_OPTIONS`) | TLS 1.3 only, `TLS_AES_256_GCM_SHA384` only | any negotiation outside this profile is a hard TLS failure, not a downgrade |

SLIs #15–17 are new with the P1 Postgres backend (`web/lib/postgresVaultRepository.js`, schema in `web/migrations/1718000000000_init-saas-schema.js`) and are now instrumented: `pwdnow_pg_query_duration_seconds{shape}` (Prometheus histogram, `web/lib/metrics.js`), scraped via the existing loopback-only `/metrics` endpoint (`server.js`). Numbers are proposed targets pending real k6 measurement at the P3 100k load test; tighten or loosen once observed.

**SLI #19 detail (CNSA 2.0 / NIST PQC L5 posture, added 2026-08-01):** `getPool()` pins `minVersion`/`maxVersion` to `TLSv1.3` and `ciphers` to `TLS_AES_256_GCM_SHA384` (never AES-128, matching [[pwdnow-crypto-baseline]]). Its `ecdhCurve` preference list is `SecP384r1MLKEM1024:X25519MLKEM768:secp384r1:X25519` — the first two are hybrid ML-KEM groups (SecP384r1MLKEM1024 mirrors the daemon's own P-384 + ML-KEM-1024 hybrid choice for PQC L5); the trailing classical groups are the fallback for today's managed Postgres/local dev, none of which speak a PQC TLS group yet. Verified against this project's Node 24 / OpenSSL 3.5.5: `SecP384r1MLKEM1024` genuinely negotiates end-to-end when both sides support it (self-contained `tls.createServer`/`tls.connect` test, both restricted to that one group with no fallback available — connection succeeded). The classical fallback is an accepted residual, not a gap: `vault_items.ciphertext` and `wrapped_dek` are already envelope-encrypted before they reach the TLS layer (see [[saas-scalability-design]] §"Data-in-transit"), so a classical-only transport leg never exposes plaintext, only ciphertext-in-transit. Local dev (`PGSSL=disable`) intentionally bypasses this profile entirely — the dev docker Postgres has no TLS listener.

The error budget for SLI #1 is 4 min 23 s per month. Two `pm2 restart` events with no graceful drain (each ~ 2 min of degraded WS) consume the entire budget. Any unplanned daemon panic adds 35 s on top.

---

## 7. Capacity model (back-of-envelope)

A single host with the current configuration can sustainably serve about:

| Quantity | Estimate | Bottleneck |
|---|---|---|
| Concurrent logged-in users (per Express process) | ~ 200 | `MAX_GLOBAL_WS_CONNECTIONS = 200` |
| WS commands / sec system-wide | ~ 1000 | FIFO single-in-flight per tab × 200 tabs × ~ 5 cmd/s sustainable |
| Unlock attempts / sec (daemon) | ~ 2 | Argon2id m=128 MiB on aarch64 ~ 400-600 ms each |
| Sync writes / sec to vault.db | ~ 50 | WAL + synchronous=NORMAL; FULL would be ~ 10 |
| Backup window cost | ~ 200 ms / GiB | `cp` blocks no other IO but corrupts WAL coverage |
| Daemon FD ceiling | 4096 | `LimitNOFILE=4096` in systemd unit |
| Express FD ceiling | OS default (often 1024 unsovered) | No explicit `LimitNOFILE` in PM2 config |

**Implications:**
- Public deployment with > 200 active users requires SPOF #1 to be fixed (cluster mode or multi-host).
- Argon2id at 400-600 ms means realistic login throughput is ~2/s — DoS by repeated unlock attempts is trivially achievable. The per-conn lockout being bypassable (issue #12) makes this real.
- Daemon FD ceiling 4096 — at 200 WS × ~ 5 fds each (peer socket + DB connections + audit log) = ~ 1000 baseline. A health-probe flood could climb fast.

---

## 8. Risk register (new — tabular for sign-off)

| ID | Risk | Likelihood | Impact | Mitigation status |
|---|---|---|---|---|
| R-01 | amd64 build fails out of the box | **Certain** at first GitHub release | Catastrophic — 100 % SLA for amd64 users | Open: §3, §10 Phase 0 |
| R-02 | Restore from hourly backup loses recent writes | High | Catastrophic — silent data loss | Open: §5.7, §10 Phase 0 |
| R-03 | Daemon swap leaks plaintext VMK to disk under PM2 mode | High when using `setup_autostart.sh` | Catastrophic — key compromise | Open: §10 Phase 0 |
| R-04 | CI green for a broken release | **Certain** today | High — every release is roulette | Open: §10 Phase 0 |
| R-05 | Lockout bypassed by reconnection | Certain — trivial | High — DoS + brute-force vector | Open: §10 Phase 1 |
| R-06 | Single daemon panic = 35 s outage = 67 % of monthly budget | Certain over time | High | Open: §10 Phase 1 |
| R-07 | Slow daemon op tears down the WS for all tabs on it | High | Medium — user-visible re-unlock | Open: §10 Phase 1 |
| R-08 | Disk failure / fs corruption with no offsite backup | Low per year per host, high over fleet | Catastrophic | Open: §10 Phase 2 |
| R-09 | TLS cert expiry / OCSP resolver outage | Medium | High | Open: §10 Phase 1 |
| R-10 | Single Express restart drops all logged-in WS sessions | Certain on every deploy | Medium per event, cumulative | Open: §10 Phase 1 |
| R-11 | Power loss with `synchronous=NORMAL` loses committed writes | Low per year, but vault data | Catastrophic — partial vault | Open: §10 Phase 1 |
| R-12 | Schema migration crashes between two version steps | Low | Catastrophic — broken vault | Open: §10 Phase 1 |
| R-13 | Cross-tenant data leak through PM2 shared file paths | Low (single-user app), high if multi-user | Catastrophic | Investigate: per-uid dir in auth_data exists; need audit |
| R-14 | Dependency CVE (e.g. ws, helmet, express, nodemailer) | Medium continuous | Medium-High | `npm audit` runs but `|| true` — fix CI then enforce |
| R-15 | Time skew breaks TOTP, JWE, OCSP | Low | High (auth outage) | Open: add NTP requirement to install docs |
| R-16 | Brave hardcoded in Playwright → E2E unrunnable in CI | Certain | High — no E2E gate exists | Open: §10 Phase 0 |
| R-17 | `pkill -9 -f "node --expose-gc"` in run script kills user's other Node processes | Low | Medium — user data loss in unrelated app | Open: §10 Phase 0 |
| R-18 | macOS user installs and gets no supervisor | Certain | High — daemon dies, no restart | Open: §10 Phase 0, ship launchd plist |
| R-19 | Cloudflare R2 sync is documented as a feature but is dead code | Certain | Medium — false trust | Open: either wire up or delete |
| R-20 | Single nginx without upstream pool blocks zero-downtime reload | Certain | Medium | Open: §10 Phase 1 |

---

## 9. Direct SLA blockers (must clear before any 99.99 % claim)

### 9.1 Cross-platform install (new top priority)
- `daemon/build.rs` cannot be released to GitHub as-is. **Fix path discovery via `pkg-config` / `llvm-config` before tagging v0.1.0.**
- CI matrix must include amd64 and arm64 Linux + macOS. Today there is no proof that any binary other than the dev-VM build works.
- Release pipeline must produce one artifact per platform and a `manifest list` Docker image.
- `setup_autostart.sh` must either (a) refuse to run on a host with `vault-daemon.service` available (and tell the user to use systemd), or (b) be deleted. Running the daemon under PM2 silently strips every sandbox guarantee.

### 9.2 Functional outages (the SLA cannot be measured until these are gone)
- **PORT default mismatch** — `web/server.js:23` falls back to `3000`; `ecosystem.config.cjs` pins `1234`. Make `1234` the only fallback. Also update `Allowed WS Origins` in `server.js:491-498` to assume the canonical port even if `PORT` is set, or compute from `PORT` consistently.
- **CI `|| true`** on lint/test/audit (`.github/workflows/ci.yml:28,30,56`) means no regression has any way to fail CI. Remove the `|| true` on `test` and `audit`. Keep on `lint` only if you really want lint-warnings to be advisory (or fix the warnings first).
- **`cargo audit -D warnings || true`** is doubly wrong: `-D warnings` makes advisories fatal, then `|| true` discards the failure. Pick one.
- **Playwright hardcodes `/usr/bin/brave-browser`** — `web/playwright.config.ts:14`. CI cannot run E2E. Either install Brave on the runner (`microsoft/setup-chromedriver`-style action) or fall back to bundled chromium.

### 9.3 Data integrity (an SLA on a corrupted vault is not an SLA)
- **Backup script does not handle WAL.** Switch from `cp vault.db` to `sqlite3 source ".backup target"`. Then `sha256sum target > target.sha256`.
- **Add a daily verify cron** that runs `sqlite3 target "PRAGMA integrity_check"` and `PRAGMA cipher_integrity_check` and alerts on fail.
- **Add a weekly restore drill** that opens the latest backup with the last-known-good key in a sandboxed process and reads N rows. Untested backups are not backups.
- **Bump `synchronous` to `FULL`** in `daemon/src/vault/db.rs:44`. Measure the throughput impact; if it's > 30 % loss, document the trade-off in `ADR-001-storage-durability.md`.
- **Wrap migrations in `BEGIN IMMEDIATE; … COMMIT;`** across the full chain (`daemon/src/vault/db.rs:70-85`).

### 9.4 Cascading failures (one fault becomes many)
- **Per-(uid, conn_id) lockout is bypassable** by simply opening a new WebSocket — `socket.rs:80` increments `CONN_COUNTER` per connection. Replace the second key with a stable client identifier: for local IPC use only `uid`; for non-local (proxied via WS) use `uid + peer_ip + tab_nonce` from the Express layer (need to pipe Express's `tab_nonce` into the daemon as part of an authenticated context).
- **FIFO WebSocket queue** — add a request-id field to msgpack frames in `daemon/src/ipc/protocol.rs`, let multiple commands be in flight per WS, and stop tearing down the whole WS on a single timeout.
- **No backpressure on `wss.on('connection')`** — `MAX_GLOBAL_WS_CONNECTIONS = 200` is a single shared counter on the only Express instance. Make this percentage-of-OS-fd-limit dynamic or move to a shared store.
- **15 sync fs ops in `auth.js`** — convert to async `fs.promises`. Single biggest event-loop unblock on the Node side.

### 9.5 Recovery-time blockers
- **No graceful drain on `SIGTERM`** in `server.js`. Add: stop accepting new WS, wait up to 25 s for in-flight to finish, then exit. Set PM2 `kill_timeout: 30000` and `wait_ready: true`.
- **No daemon graceful drain.** On `SIGTERM`, mark `accept_loop = false`, drain in-flight to 10 s, then exit.
- **Cut WatchdogSec to 10 s** with heartbeat at 3 s — failed daemons recover faster.
- **No PM2 `reload` path.** Even after externalising state, `npm run pm2:restart` is hard stop+start; `pm2 reload` (zero-downtime) requires cluster mode.

---

## 10. Phased roadmap to 100 / 100 (= 99.99 %)

Effort estimate assumes one senior engineer full-time. Each phase delivers a measurable SLA increment.

### Phase 0 — STOP THE BLEED (1 week → ~ 32/100)
Non-negotiable. Until this is done, no SLA can be measured and the project can't ship to GitHub honestly.

1. **`daemon/build.rs`** — replace all hardcoded paths:
   ```rust
   // BAD (current):
   println!("cargo:rustc-link-search=native=/usr/lib/aarch64-linux-gnu");
   println!("cargo:rustc-env=LIBCLANG_PATH=/usr/lib/llvm-21/lib");

   // GOOD: use pkg-config for libs, llvm-config for clang
   let sodium = pkg_config::Config::new().probe("libsodium").expect("libsodium");
   let sqlcipher = pkg_config::Config::new().probe("sqlcipher").expect("sqlcipher");
   let fido2 = pkg_config::Config::new().probe("libfido2").expect("libfido2");
   let libclang = std::process::Command::new("llvm-config")
       .arg("--libdir").output().expect("llvm-config not found");
   println!("cargo:rustc-env=LIBCLANG_PATH={}",
       String::from_utf8_lossy(&libclang.stdout).trim());
   ```
   Add a fallback for `LIBCLANG_PATH` via `LIBCLANG_PATH` env var.
2. **Add `rust-toolchain.toml`** at `daemon/`:
   ```toml
   [toolchain]
   channel = "1.80.1"
   components = ["clippy", "rustfmt"]
   targets = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "x86_64-apple-darwin"]
   ```
3. **PORT canonicalisation** — `web/server.js:23` → `|| 1234`. Audit every `localhost:3000`, `127.0.0.1:3000`, `:3000` in the tree.
4. **CI: remove `|| true`** from lint/test/audit lines. Make CI able to fail. Pin the `dtolnay/rust-toolchain` to a specific version.
5. **CI matrix:** add `runs-on: ubuntu-24.04-arm` for the daemon-tests and web-tests jobs. (As of 2026, GitHub-hosted arm64 is free for public repos.)
6. **Release matrix:** use a `strategy.matrix` with `[ubuntu-24.04, ubuntu-24.04-arm, macos-14]` so each release publishes `vault-daemon-linux-amd64`, `vault-daemon-linux-arm64`, `vault-daemon-macos-arm64`. Cosign-sign each.
7. **Multi-arch container:** rewrite `deploy/Dockerfile` with `FROM --platform=$BUILDPLATFORM` and `cargo build --target $TARGET`; publish via `docker buildx build --platform linux/amd64,linux/arm64 --push`.
8. **Ship `deploy/launchd/com.pwdnow.vault-daemon.plist`** for macOS.
9. **Ship `deploy/openrc/vault-daemon`** for Alpine/Gentoo.
10. **Backup script: switch to SQLite online backup API.** Edit `deploy/vault-daemon-backup.service`:
    ```bash
    ExecStart=/bin/bash -c '\
      DEST=/var/backups/vault-daemon; \
      mkdir -p "$DEST"; \
      sqlite3 /var/lib/vault-daemon/vault.db ".backup $DEST/vault-$(date +%%s).db"; \
      sha256sum "$DEST/vault-$(date +%%s).db" > "$DEST/vault-$(date +%%s).db.sha256"; \
      find "$DEST" -name "vault-*.db" -mtime +30 -delete; \
      find "$DEST" -name "vault-*.db.sha256" -mtime +30 -delete'
    ```
11. **Backup verify cron** — daily systemd timer that runs `sqlite3 latest_backup "PRAGMA integrity_check; PRAGMA cipher_integrity_check"` and alerts on fail.
12. **Add `/metrics`** Prometheus endpoint on both Express and daemon (`prom-client` for Node; `axum` + `metrics-exporter-prometheus` for Rust). Even if no Prometheus is running yet, having the endpoint enables future scraping.
13. **External synthetic monitor** — UptimeRobot / BetterUptime / self-hosted Uptime Kuma probing `https://vault.local/health` every 30 s from at least one off-host probe.
14. **Disable or rewrite `setup_autostart.sh`** to use systemd (`sudo systemctl enable --now vault-daemon vault-daemon-backup.timer pwdnow-monitor pwdnow`) instead of demoting the daemon to PM2.
15. **Fix `run_pwdnow.sh`** — replace `pkill -9 -f "node --expose-gc"` with PID-tracking (`kill $(cat .daemon.pid)`).
16. **Playwright fallback** — change `executablePath: '/usr/bin/brave-browser'` to env-driven (`process.env.BRAVE_BROWSER || undefined`); if undefined, use Playwright's bundled chromium.
17. **Wire Cloudflare R2 sync OR delete it.** If wiring: add `Request::SyncNow`, `Request::SyncStatus`, a `tokio::time::interval(60 * 60)` driver, and surface in the UI. If deleting: `rm daemon/src/sync/cloudflare.rs` and update the architecture docs.

**Expected post-Phase-0 score: ~ 32/100. SLA measurable on a single host. amd64 audience can install. Realistic effective availability: 99.0 %.**

### Phase 1 — HARDEN THE SINGLE HOST (3 weeks → ~ 55/100, ~ 99.5 %)
1. **Externalise Express in-memory state** to a lmdb-js or SQLite WAL file mounted next to the daemon — SETUP_TOKEN, wsConnectCounts, wsNonceCounts, SRI cache, active JWE JTIs, lockout counters.
2. **Switch PM2 to cluster mode** once state is externalised (`instances: 'max', exec_mode: 'cluster'`). Add `wait_ready: true` and `kill_timeout: 30000`.
3. **Graceful shutdown** in `server.js`: handle `SIGTERM`, refuse new WS, drain in-flight for 25 s, close listener, exit. Send `process.send('ready')` after binding so PM2 knows.
4. **Daemon graceful drain:** on `SIGTERM`, stop accepting new connections, drain in-flight to 10 s, then exit. Cut `WatchdogSec` to 10 s with 3-s heartbeat.
5. **WS request multiplexing:** add a 32-bit `request_id` to msgpack frames, hold a `HashMap<request_id, oneshot::Sender>` in `daemonClient.ts`. Eliminates FIFO cascading-fail.
6. **Circuit breaker:** after 5 consecutive errors or 5 s avg latency between Express and daemon, fast-fail with 503 + `Retry-After: 5` for 30 s.
7. **Daemon socket reconnect** in `server.js` — exponential backoff 100 ms → 2 s, 5 retries before propagating to WS. A daemon restart becomes a hiccup.
8. **`systemd Sockets=vault-daemon.socket`** with `Accept=no` — systemd owns the socket and hands it to the daemon, so a daemon restart never leaves a stale socket file.
9. **SQLite tuning:** `synchronous=FULL`, periodic `wal_checkpoint(TRUNCATE)` every 5 min, periodic `cipher_integrity_check` every hour.
10. **Migration atomicity:** wrap `apply_migrations` in a single `BEGIN IMMEDIATE; … COMMIT;` so partial migrations roll back.
11. **Sync writes async** in `auth.js`: replace all 15 `writeFileSync`/`readFileSync` calls with `fs.promises`. Add `proper-lockfile` for cross-process file locks (already a dependency).
12. **Wire Cloudflare R2 sync into a 5-min timer.** RPO drops from 1 h local to 5 min offsite.
13. **Nginx upstream block** even with one backend; enables passive health checks and zero-config future failover.
14. **Per-instance TLS cert automation** — ship a `certbot` recipe (HTTP-01 or DNS-01).
15. **Per-instance install doc** — `INSTALL-linux.md`, `INSTALL-macos.md`, `INSTALL-docker.md`, `INSTALL-alpine.md`.

**Expected post-Phase-1 score: ~ 55/100. Realistic effective availability: 99.5 %.**

### Phase 2 — TWO HOSTS, ACTIVE-PASSIVE (6 weeks → ~ 78/100, ~ 99.95 %)
1. **Second identical host**, same systemd units, daemon configured as standby (syncs from primary R2 every 60 s, refuses WS until promoted).
2. **Litestream** — replaces hourly `sqlite3 .backup` with continuous WAL streaming to S3/R2. RPO drops to seconds.
3. **Floating IP / DNS failover** — keepalived (on-prem) or low-TTL DNS (cloud) in front of both Nginx instances.
4. **Promote-on-failure script** with explicit RPO/RTO checks: probe primary, pull latest WAL from R2, run `cipher_integrity_check`, take floating IP, advertise health.
5. **Session externalisation** — JWE cookies are stateless, but the active JTI revocation map must move to a shared KV. Simplest: write revocation list to a file on shared storage; check on each request (cache in memory with short TTL).
6. **Quarterly DR drill** — measure RTO empirically; document recovery time; iterate.

**Expected post-Phase-2 score: ~ 78/100. Realistic effective availability: 99.95 %. Single-host monthly outage budget grows from 4 min 23 s to 22 min — enough for routine deploys.**

### Phase 3 — TWO HOSTS, ACTIVE-ACTIVE (6 weeks → ~ 92/100)
1. **Shared storage** — Ceph or EFS for vault files; or shard per-user across hosts via consistent hashing on user UUID.
2. **CRDT for shared mutable state** — lockout counters, challenge map.
3. **Sticky WS sessions** by `tab_nonce` hash → consistent host; or pub/sub for cross-host session messages (Redis Streams / NATS).
4. **Blue-green deploys** with canary on 1 % of traffic for 10 min, watched against SLI burn rate.

**Expected post-Phase-3 score: ~ 92/100. Realistic effective availability: 99.95–99.99 % depending on shared-storage SLA.**

### Phase 4 — MULTI-REGION + ERROR BUDGET CULTURE (8 weeks → 100, 99.99 %)
1. **Second region** with async vault replication; one writer per user, geo-routed.
2. **Chaos engineering** — monthly fault injection (kill -9 daemon; drop 10 % WS frames; fill disk; expire cert in staging; corrupt sidecar tmp file).
3. **SLO + error budget governance** — 99.99 % monthly; 50 % budget burn in 1 h pages; 100 % burn freezes deploys.
4. **Status page** fed by ≥ 3 external probes from different ISPs.
5. **On-call rotation; runbooks for every alert; postmortem-on-every-burn culture.**
6. **Quarterly DR drill** with full cert rotation: prove RTO ≤ 60 s, RPO ≤ 60 s.

---

## 11. Per-platform deployment recipes (skeleton for INSTALL docs)

### Linux Debian/Ubuntu (amd64 + arm64)
```bash
# 1. Install deps
sudo apt-get update
sudo apt-get install -y \
  build-essential pkg-config libclang-dev \
  libsodium-dev libfido2-dev libsqlcipher-dev liboqs-dev \
  nginx certbot
# 2. Install rustup + toolchain pinned by rust-toolchain.toml
curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs | sh -s -- -y
# 3. Build + install
cd PWDnow/deploy && sudo make install
# 4. Enable services
sudo systemctl enable --now vault-daemon vault-daemon-backup.timer pwdnow-monitor pwdnow
# 5. Obtain TLS cert
sudo certbot --nginx -d vault.example.com
```

### Linux RHEL/Fedora/Rocky (amd64 + arm64)
```bash
# 1. Install deps
sudo dnf install -y \
  gcc make pkgconf clang-devel \
  libsodium-devel libfido2-devel sqlcipher-devel liboqs-devel \
  nginx certbot
# 2-5. Same as Debian, plus SELinux policy:
sudo restorecon -Rv /var/lib/vault-daemon /run/vault-daemon
# (ship deploy/selinux/vault-daemon.te + .fc for production)
```

### Linux Alpine (amd64 + arm64)
```bash
# 1. Install deps (musl)
sudo apk add build-base pkgconf clang-dev \
  libsodium-dev libfido2-dev sqlcipher-dev nginx certbot
# 2-3. Build (rust-toolchain.toml must include x86_64-unknown-linux-musl)
# 4. OpenRC service
sudo rc-update add vault-daemon default
sudo rc-service vault-daemon start
```

### macOS arm64 / x64 (native)
```bash
# 1. Install deps via Homebrew
brew install rustup-init pkg-config libsodium sqlcipher libfido2 liboqs llvm
rustup-init -y
# 2. Build
cd PWDnow/daemon && cargo build --release --features pq-hybrid-1024
# 3. Install launchd plist
sudo cp deploy/launchd/com.pwdnow.vault-daemon.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.pwdnow.vault-daemon.plist
# Note: macOS has no AppArmor; security relies on launchd + entitlements + Gatekeeper
```

### Docker (multi-arch via buildx)
```bash
# Maintainer side:
docker buildx create --use --name pwdnow-builder
docker buildx build --platform linux/amd64,linux/arm64 \
  -t pwdnow/vault-daemon:0.1.0 -t pwdnow/vault-daemon:latest \
  --push deploy/
# User side:
docker run -d --name pwdnow-daemon \
  --cap-add=IPC_LOCK --memory-swappiness=0 \
  -v vault-data:/var/lib/vault-daemon \
  -v vault-socket:/run/vault-daemon \
  pwdnow/vault-daemon:latest
```

(Docker without `--cap-add=IPC_LOCK` cannot mlock and silently allows VMK to swap. Document loudly.)

### Windows + WSL2
Document: install Ubuntu 22.04+ in WSL2 ≥ 0.67.6 (systemd support), then follow Debian recipe. Note that systemd watchdog under WSL2 has edge cases — use `pwdnow-monitor` as belt-and-suspenders.

---

## 12. Chaos engineering test plan (new)

Run monthly in staging; quarterly in production with traffic shadowed.

| Test | Inject | Expected behaviour | SLA impact |
|---|---|---|---|
| Daemon kill -9 | `pkill -9 vault-daemon` | systemd restarts in ≤ 10 s; pwdnow-monitor detects and alerts WARN; existing WS reconnect within 5 s with hiccup invisible to UI | Should not consume > 30 s of monthly budget |
| Daemon hang | `kill -STOP $(pidof vault-daemon)` for 60 s, then `-CONT` | systemd watchdog kills after 10 s; restart cycle as above | Should not exceed 30 s outage |
| Express OOM | malloc loop in test route | PM2 hits `max_memory_restart`, hard restarts; WS reconnect storm | Reveals lack of graceful drain |
| Disk fill | `dd if=/dev/zero of=/tmp/fill bs=1M count=N` until 92 % | `pwdnow-monitor` triggers `auto_prune_logs`; CRIT alert fires; cluster_threshold cleared | Validates monitor's auto-prune |
| Nginx config break | inject syntax error, reload | reload fails atomically; old process keeps serving | Validates `nginx -t` gate |
| Cert near-expiry | stash a cert valid for 5 days | SLI #8 fires WARN; ops sees days remaining | Validates cert monitoring |
| WAL corruption | dd zeros into vault.db-wal mid-flight | `cipher_integrity_check` fails on next open; daemon refuses to serve; pwdnow-monitor alerts CRIT | Validates corruption detection |
| Backup corruption | flip a byte in latest backup | daily verify cron fails; alert fires | Validates verify cron |
| WS slowloris | open 200 WS, don't send data | `handshake timeout` 10 s closes each; counter resets | Validates server.js:543 |
| WS flood from one IP | 30 WS/min × 1 IP | `WS_CONNECT_LIMIT` fires after 30; subsequent close 1013 | Validates server.js:528 |
| Reconnect-bypass lockout | 100 unlock attempts each on a new WS | Today: succeeds (no lockout). After Phase 1 fix: locked out at 5 | Validates lockout scoping |
| Daemon restart during unlock | restart daemon mid-Argon2id | Browser sees WS close; retries; succeeds. Today: re-runs entire unlock UX | Validates graceful drain |
| Cross-arch CI matrix | run release on a fresh arm64 + amd64 Mac + Alpine VM | Each builds; smoke-test passes; artifacts cosign-verified | Validates portability |

---

## 13. Runbook outlines (skeleton — full runbooks per incident class)

Each runbook follows the SRE format: detect → diagnose → contain → eradicate → recover → postmortem.

- **RB-01: Daemon won't start (POST failure)** — check journal, `exit_code = 42` means FIPS POST failed; bisect crypto module; never restart in a loop.
- **RB-02: Daemon CPU pegged** — check `cipher_integrity_check` time, Argon2id load, perf record.
- **RB-03: Express OOM repeated** — check `max_memory_restart` rate, dump heap, identify leak.
- **RB-04: Vault won't open after restart** — `cipher_integrity_check failed`; restore from last verified backup; document RPO loss.
- **RB-05: WS connections all closing 1013** — `MAX_GLOBAL_WS_CONNECTIONS` exceeded; check for connection leak; raise limit if legitimate.
- **RB-06: TLS cert near expiry / expired** — manual `certbot renew --force-renewal`; reload nginx; postmortem.
- **RB-07: Backup verify failing** — check disk health (smartctl); check source DB integrity; investigate before next backup.
- **RB-08: pwdnow-monitor alert flood** — check cooldown; investigate root cause; never silence without ticket.
- **RB-09: User reports lockout from a fresh login** — confirm per-(uid, conn_id) bypass not regressed; check for genuine compromise.
- **RB-10: Release pipeline failing on one arch** — block release; identify regression; do not ship single-arch.

---

## 14. Quick wins (1–4 hours each, do these first)

| # | Change | Δ SLA score | Effort |
|---|---|---|---|
| 1 | `web/server.js:23` → `|| 1234` | +1 | 5 min |
| 2 | Remove `|| true` from CI test/audit | +3 | 30 min |
| 3 | Fix Playwright to use bundled chromium | +1 | 15 min |
| 4 | Add `rust-toolchain.toml` pinning rustc 1.80.x | +1 | 5 min |
| 5 | Backup script: `sqlite3 .backup` + sha256sum sidecar | +2 | 1 h |
| 6 | Daily backup-verify systemd timer | +1 | 1 h |
| 7 | Express `SIGTERM` graceful drain + `kill_timeout: 30000` + `wait_ready: true` | +2 | 2 h |
| 8 | Daemon `SIGTERM` graceful drain + WatchdogSec=10s | +2 | 2 h |
| 9 | Replace 15 sync fs ops in auth.js with `fs.promises` | +1 | 2 h |
| 10 | `synchronous=FULL` + measure throughput | +1 | 1 h |
| 11 | Migrations in single `BEGIN IMMEDIATE; … COMMIT;` | +1 | 1 h |
| 12 | `pkg-config`-driven `build.rs` (kill aarch64 hardcode) | +5 | 3 h |
| 13 | CI matrix: add arm64 + macos | +3 | 2 h |
| 14 | Release matrix: per-arch artifacts | +3 | 4 h |
| 15 | Nginx `upstream { ... }` even with one backend | +1 | 30 min |
| 16 | Express `/metrics` Prometheus endpoint | +1 | 2 h |
| 17 | Disable or rewrite `setup_autostart.sh` | +2 | 1 h |
| 18 | `pwdnow-monitor.toml: min_severity = "warn"` | +1 | 5 min |
| 19 | Fix `run_pwdnow.sh` pkill blast | +1 | 30 min |
| 20 | macOS launchd plist | +1 | 2 h |

**Quick-win total: +33 pts → ~ 50/100 in two engineer-weeks. After that, only architectural change moves the needle further.**

---

## 15. The port-1234 cleanup (you flagged this)

There is no single source of truth for the port. Audit + fix:

| Location | Value | Fix |
|---|---|---|
| `web/server.js:23` | `process.env.PORT \|\| 3000` | → `\|\| 1234` |
| `web/ecosystem.config.cjs:13,17` | `PORT: 1234` | OK |
| `web/playwright.config.ts:8,31` | `http://localhost:1234`, `http://127.0.0.1:1234` | OK (correct already) |
| `web/.env.example` | (unreadable here) | Add explicit `PORT=1234` with comment "must match nginx upstream and ecosystem.config.cjs" |
| `deploy/nginx/vault.conf:135-139,153,158,164` | `127.0.0.1:1234` | OK |
| `server.js:491-498` Allowed WS Origins | computed from `PORT` | OK only after fix #1 |

Add a startup assertion:
```js
if (process.env.NODE_ENV === 'production' && PORT !== 1234) {
  console.warn(`Production PORT is ${PORT}, but nginx expects 1234. This will cause 502.`);
}
```

---

## 16. macOS-M1-in-Parallels considerations

The dev environment context (a single user has tested the entire stack only on aarch64 Ubuntu inside a Parallels VM on a Mac M1) explains every aarch64 hardcode in the tree. It also means:

1. **The author has likely never seen the daemon build fail** because cargo always finds `/usr/lib/aarch64-linux-gnu` in this VM. The day the first amd64 GitHub user files an issue is the day this gets discovered the hard way.
2. **macOS-native install has never been tested** because the user runs everything inside Linux VMs. macOS-native lacks libsodium/libfido2/libsqlcipher in `/usr/lib`; they're in `/opt/homebrew/lib`. The current `build.rs` will fail.
3. **Parallels Desktop adds a hypervisor layer** that introduces its own pause-on-snapshot, VM-resume clock skew, and balloon-driver memory pressure events. None of these are accounted for in the daemon's clock-based logic (TOTP, JWE `exp`, OCSP staple cache). Test on bare metal too.
4. **Filesystem semantics differ**: Parallels' shared folders use a Linux client that doesn't fully honour `fsync` semantics. Backups created in a shared folder may not be durable. Daemon should refuse to put `vault.db` on shared folders by checking `statfs` `f_fsid` and rejecting known shared-FS magic numbers.
5. **The Mac sleeps**: when the host suspends, the guest VM is paused. On resume, every TCP keepalive and TLS session in flight has stalled for minutes-to-hours. Browser will reconnect. Daemon's TOTP/JWE windows need to tolerate a clock jump (most do; verify).

---

## 17. Summary verdict for the architect

**Today: 17 / 100.**

PWDnow is a strong **single-host single-user** zero-knowledge vault with FIPS-grade POST, multi-slot challenge tracking, watchdog plumbing, SBOM-and-cosign supply chain, and SRE-flavoured self-heal. **It is not an SLA 99.99 % architecture** and cannot become one without topology change. The realistic single-host ceiling — even with every quick win applied — is ~ 99.5 % (43 h/year).

**The dominant risk for the public-GitHub launch is not availability, it is portability.** The current build will only succeed for the exact dev environment (Linux arm64 Ubuntu inside Parallels). Half the GitHub audience will hit a hard build failure within minutes of `git clone`. That is 100 % SLA loss per amd64 user. Phase 0 of the roadmap exists primarily to fix this before tagging v0.1.0.

**Path to defensible 99.99 %:** ~ 6 calendar months of focused engineering on top of the existing crypto core.
- Phase 0 (1 week): portability + measurability. Score → 32.
- Phase 1 (3 weeks): single-host hardened to its theoretical maximum. Score → 55, realistic 99.5 %.
- Phase 2 (6 weeks): two-host active-passive + Litestream + R2 sync. Score → 78, realistic 99.95 %.
- Phase 3 (6 weeks): active-active + CRDT shared state. Score → 92.
- Phase 4 (8 weeks): multi-region + chaos + SLO governance. Score → 100, 99.99 %.

The cryptographic story is genuinely research-grade. The availability story is the gap, and every step above uses well-understood patterns. The honest milestone for a self-hosted password manager is probably **Phase 2's 99.95 %** — beyond that, the operational cost (chaos engineering, on-call rotation, multi-region replication) outweighs the marginal benefit for most users. State 99.95 % publicly and design for it; quietly engineer toward 99.99 % only if a paying enterprise customer asks for the contract.

— End of v2 assessment —
