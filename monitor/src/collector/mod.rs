//! Collector module — defines the shared `Snapshot` type and the `Collector` trait.
//! Each sub-module implements one area of concern (system, daemon, web).

pub mod cert;
pub mod daemon;
pub mod system;
pub mod web;

use serde::Serialize;

/// A fully populated snapshot of all metrics from one poll cycle.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Snapshot {
    /// Unix timestamp (seconds) when this snapshot was taken
    pub ts_secs: i64,

    // ── System metrics ─────────────────────────────────────────────────────────
    /// RAM available in MiB
    pub ram_available_mib:  f64,
    /// RAM total in MiB
    pub ram_total_mib:      f64,
    /// Swap free in MiB
    pub swap_free_mib:      f64,
    /// CPU usage % (0–100), averaged across all cores since last poll
    pub cpu_usage_pct:      f64,
    /// 1-minute load average
    pub load_avg_1:         f64,
    /// Disk usage % for the root filesystem
    pub disk_used_pct:      f64,
    /// Disk free GiB for the root filesystem
    pub disk_free_gib:      f64,
    /// Disk I/O utilisation % (time disk was busy)
    pub disk_io_pct:        f64,

    // ── vault-daemon health ────────────────────────────────────────────────────
    /// Is vault-daemon.service active according to systemctl?
    pub daemon_active:      bool,
    /// Did the Unix socket respond within the configured timeout?
    pub daemon_socket_ok:   bool,
    /// Round-trip connect time to the socket in milliseconds
    pub daemon_socket_ms:   f64,

    // ── Web / PM2 health ───────────────────────────────────────────────────────
    /// Is the PM2 process "online"?
    pub web_pm2_online:     bool,
    /// PM2 restart count for this process (monotonic, reset on pm2 restart)
    pub web_pm2_restarts:   u32,
    /// Did the TCP port respond?
    pub web_port_open:      bool,
    /// Did GET /health return 200?
    pub web_health_ok:      bool,
    /// HTTP round-trip time in milliseconds
    pub web_health_ms:      f64,

    // ── nginx health ───────────────────────────────────────────────────────────
    /// Is nginx.service active?
    pub nginx_active:       bool,
    /// Is port 443 open?
    pub nginx_port_ok:      bool,

    // ── TLS certificate expiry ─────────────────────────────────────────────────
    /// Minimum days until expiry across all configured cert paths.
    /// `None` = no cert configured or unreadable (treated as a separate
    /// "cert_unknown" warning by the risk engine).
    pub tls_cert_days_left: Option<i64>,
}

impl Snapshot {
    pub fn with_ts(ts_secs: i64) -> Self {
        Self { ts_secs, ..Default::default() }
    }
}
