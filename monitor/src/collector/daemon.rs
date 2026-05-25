//! vault-daemon health collector.
//! Uses two independent checks:
//!   1. `systemctl is-active vault-daemon` — systemd view of the process
//!   2. Unix domain socket connect-test — actual IPC responsiveness

use std::io;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use tracing::debug;

use super::Snapshot;
use crate::config::Config;

pub struct DaemonCollector;

impl DaemonCollector {
    pub fn new() -> Self { Self }

    pub fn collect(&self, snap: &mut Snapshot, cfg: &Config) {
        // ── 1. systemctl is-active ────────────────────────────────────────────
        snap.daemon_active = check_systemctl_active("vault-daemon");

        // ── 2. Unix socket connect test ───────────────────────────────────────
        let timeout = Duration::from_millis(cfg.thresholds.socket_timeout_ms);
        let t0 = Instant::now();
        match unix_connect_test(&cfg.paths.vault_socket, timeout) {
            Ok(())  => {
                snap.daemon_socket_ok = true;
                snap.daemon_socket_ms = t0.elapsed().as_secs_f64() * 1000.0;
                debug!("vault-daemon socket OK in {:.1}ms", snap.daemon_socket_ms);
            }
            Err(e) => {
                snap.daemon_socket_ok = false;
                snap.daemon_socket_ms = t0.elapsed().as_secs_f64() * 1000.0;
                debug!("vault-daemon socket error: {e}");
            }
        }
    }
}

/// Returns true if `systemctl is-active <service>` exits with code 0.
/// Uses `std::process::Command` — ~1ms, acceptable at 10s poll interval.
pub fn check_systemctl_active(service: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", service])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Attempt to connect to a Unix domain socket within `timeout`.
/// We only test that the connection succeeds — we don't send any data,
/// which preserves the daemon's SO_PEERCRED auth (a probe UID != vault UID
/// will be cleanly rejected, but the ACCEPT proves the daemon is listening).
fn unix_connect_test(path: &std::path::Path, timeout: Duration) -> io::Result<()> {
    // First check existence to avoid blocking on connect to a missing socket
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "socket file does not exist",
        ));
    }

    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    // The connection itself succeeding is enough evidence the daemon is alive.
    // Drop the stream cleanly.
    drop(stream);
    Ok(())
}
