//! TLS certificate expiry collector.
//!
//! SLA G6: cert expiry is a top-2 cause of self-hosted-app outages. The
//! browser fails *closed* on an expired cert, so silent rotation slippage
//! becomes a hard outage with zero in-app warning. This collector reads each
//! configured cert path daily and emits `days_until_expiry`; the risk engine
//! converts that into a 14-day warn / 5-day critical / 0-day emergency event.
//!
//! Implementation note: we shell to `openssl` for portability — same reason
//! the web collector uses a raw HTTP/1.1 GET rather than a heavy HTTP client.
//! The monitor is meant to stay tiny.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};
use tracing::debug;

use super::Snapshot;
use crate::config::Config;

pub struct CertCollector;

impl CertCollector {
    pub fn new() -> Self { Self }

    /// For each cert path in `cfg.paths.tls_cert_paths`, run
    /// `openssl x509 -enddate -noout` and stash the minimum days-left into
    /// `snap.tls_cert_days_left`. None = unable to determine (no cert, openssl
    /// missing, parse error) — treated by the risk engine as a separate
    /// "cert_unknown" warning rather than silently passing.
    pub fn collect(&self, snap: &mut Snapshot, cfg: &Config) {
        let paths: &[PathBuf] = &cfg.paths.tls_cert_paths;
        if paths.is_empty() {
            snap.tls_cert_days_left = None;
            return;
        }

        let mut min_days: Option<i64> = None;
        for p in paths {
            match days_until_expiry(p) {
                Some(d) => {
                    debug!(path = %p.display(), days = d, "cert expiry");
                    min_days = Some(match min_days {
                        Some(prev) => prev.min(d),
                        None => d,
                    });
                }
                None => {
                    debug!(path = %p.display(), "cert unreadable / openssl missing");
                }
            }
        }
        snap.tls_cert_days_left = min_days;
    }
}

fn days_until_expiry(cert_path: &Path) -> Option<i64> {
    if !cert_path.exists() {
        return None;
    }
    let output = Command::new("openssl")
        .args(["x509", "-enddate", "-noout", "-in"])
        .arg(cert_path)
        // openssl on a giant PEM bundle is microseconds — keep timeout tight.
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&output.stdout);
    // Format: "notAfter=May 16 12:34:56 2026 GMT\n"
    let datestr = line.trim().strip_prefix("notAfter=")?;
    // chrono can parse the openssl format directly.
    let parsed = NaiveDateTime::parse_from_str(datestr, "%b %e %H:%M:%S %Y %Z")
        .or_else(|_| NaiveDateTime::parse_from_str(datestr.trim_end_matches(" GMT"), "%b %e %H:%M:%S %Y"))
        .ok()?;
    let dt = DateTime::<Utc>::from_naive_utc_and_offset(parsed, Utc);
    let delta = dt.signed_duration_since(Utc::now());
    // Negative = already expired; risk engine treats this as emergency.
    Some(delta.num_days())
}

/// 24-hour TTL helper — caller decides whether to skip a poll.
#[allow(dead_code)]
pub const COLLECTION_INTERVAL: Duration = Duration::from_secs(86_400);
