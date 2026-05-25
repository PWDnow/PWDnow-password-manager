mod auth;
mod crypto;
mod error;
mod ipc;
mod sync;
mod vault;
#[cfg(test)]
mod tests_senior;

use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

use error::VaultError;
use ipc::socket::SocketListener;
use vault::state::DaemonState;

const DEFAULT_SOCKET_PATH: &str = "/run/vault-daemon/vault.sock";
const DEFAULT_VAULT_PATH:  &str = "vault.db";

/// Parse a `--flag value` pair from `argv`.
fn arg_value(flag: &str) -> Option<PathBuf> {
    let args: Vec<String> = std::env::args().collect();
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| PathBuf::from(&w[1]))
}

#[tokio::main]
async fn main() -> Result<(), VaultError> {
    // M-51 fix: disable core dumps to prevent sensitive data (VMK, credentials)
    // from leaking to disk if the daemon crashes.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    unsafe {
        libc::umask(0o077);
    }
    
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .compact()
        .init();

    let socket_path = arg_value("--socket")
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH));
    let vault_path = arg_value("--vault")
        .unwrap_or_else(|| PathBuf::from(DEFAULT_VAULT_PATH));

    info!(socket = %socket_path.display(), vault = %vault_path.display(), "vault-daemon starting");

    // FIPS 140-3 §AS09 power-on self-tests — must pass before advertising readiness.
    if let Err(e) = crypto::self_test::run_post() {
        error!("FIPS POST failed: {e}");
        std::process::exit(42);
    }
    info!("FIPS 140-3 POST passed");

    // Clean up any stale tmp files left by an interrupted wipe or header write.
    if let Some(dir) = vault_path.parent() {
        for suffix in &["meta.wipe_tmp", "meta.tmp"] {
            let stale = dir.join(format!("vault.db.{suffix}"));
            if stale.exists() {
                let _ = std::fs::remove_file(&stale);
                info!("cleaned stale tmp file: {}", stale.display());
            }
        }
    }

    let state = Arc::new(DaemonState::new(vault_path));

    #[cfg(target_os = "linux")]
    sd_notify::notify(true, &[sd_notify::NotifyState::Ready])
        .map_err(|e| VaultError::Ipc(format!("sd_notify Ready failed: {}", e)))?;

    // SLA P4: dispatch-driven watchdog. The old loop fired WATCHDOG=1 from a
    // free-running timer — a deadlocked dispatcher kept the heartbeat going
    // and systemd never restarted us. Now: every tick we check whether any
    // request is in flight and whether one has completed in the stall window.
    // If pending > 0 and no completion in `stall_secs`, the daemon is wedged
    // → we skip the heartbeat → systemd restarts after `WatchdogSec`.
    // Idle daemons still tick normally (in_flight == 0 ⇒ no wedge possible).
    #[cfg(target_os = "linux")]
    if let Ok(usec_str) = std::env::var("WATCHDOG_USEC") {
        if let Ok(usec) = usec_str.parse::<u64>() {
            let interval = std::time::Duration::from_micros(usec / 3);
            let stall_secs = ((usec / 1_000_000) * 2 / 3).max(5);
            let state_for_wd = Arc::clone(&state);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                loop {
                    ticker.tick().await;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs()).unwrap_or(0);
                    let in_flight = state_for_wd.in_flight_requests.load(std::sync::atomic::Ordering::Relaxed);
                    let last_done = state_for_wd.last_completion_secs.load(std::sync::atomic::Ordering::Relaxed);
                    let wedged = in_flight > 0 && now.saturating_sub(last_done) >= stall_secs;
                    if wedged {
                        let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Status(
                            &format!("WEDGED: in_flight={in_flight} last_done={}s ago", now - last_done)
                        )]);
                        continue;
                    }
                    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
                    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Status(
                        &format!("ok in_flight={in_flight}")
                    )]);
                }
            });
        }
    }

    // SLA C3: WAL checkpoint timer. Without this the WAL grows during long
    // sessions; crash recovery becomes proportional to WAL size (seconds →
    // minutes). PRAGMA wal_checkpoint(TRUNCATE) caps it; safe with active
    // readers. We use try_lock so a busy writer never blocks the checkpoint
    // task (and vice versa).
    let state_for_wal = Arc::clone(&state);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        ticker.tick().await; // skip the immediate first tick
        loop {
            ticker.tick().await;
            let _ = (|| -> Option<()> {
                let guard = state_for_wal.db.try_lock().ok()?;
                let conn = guard.as_ref()?;
                let _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)", []);
                Some(())
            })();
        }
    });

    let listener = SocketListener::bind(&socket_path, Arc::clone(&state)).await
        .map_err(|e| VaultError::Ipc(format!("SocketListener::bind failed: {}", e)))?;

    tokio::select! {
        result = listener.run() => {
            if let Err(e) = result { error!(err = %e, "socket listener error"); }
        }
        _ = signal::ctrl_c() => {
            info!("SIGINT received — locking vault, draining (10 s)");
            state.lock();
            // Brief drain: let in-flight IPC handlers finish before exit.
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
        _ = async {
            #[cfg(unix)]
            {
                let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate()).unwrap();
                sigterm.recv().await;
            }
            #[cfg(not(unix))]
            {
                tokio::time::sleep(std::time::Duration::from_secs(999999)).await;
            }
        } => {
            info!("SIGTERM received — locking vault, draining (10 s)");
            state.lock();
            // Notify systemd that we are stopping (suppresses watchdog during drain).
            #[cfg(target_os = "linux")]
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]);
            // Give in-flight handlers up to 10 s to finish.
            // TimeoutStopSec in the service file is 15 s; systemd will SIGKILL after that.
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }
    Ok(())
}
