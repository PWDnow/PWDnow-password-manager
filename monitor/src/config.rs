//! Configuration — loaded once at startup from a TOML file.
//! All fields have safe defaults so the binary works out-of-the-box.

use serde::Deserialize;
use std::path::PathBuf;

/// Top-level config (mirrors /etc/pwdnow-monitor.toml).
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct Config {
    /// How often to poll, in seconds.
    pub poll_interval_secs: u64,

    /// Paths to watch
    pub paths: PathsConfig,

    /// Thresholds that trigger warnings / critical alerts
    pub thresholds: ThresholdConfig,

    /// Auto-healing behaviour
    pub healing: HealingConfig,

    /// Log output
    pub log: LogConfig,

    /// Notifications
    pub notify: NotifyConfig,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct PathsConfig {
    pub vault_socket:   PathBuf,
    pub vault_db:       PathBuf,
    pub vault_log_dir:  PathBuf,
    pub pm2_home:       PathBuf,
    pub web_port:       u16,
    pub health_endpoint: String,
    /// SLA G6: TLS certs to watch for expiry. Empty = collector is a no-op.
    pub tls_cert_paths: Vec<PathBuf>,
    /// Directory holding hourly vault backups (used for freshness check).
    pub backup_dir:     PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct ThresholdConfig {
    /// Disk usage % at which WARNING fires
    pub disk_warn_pct:     f64,
    /// Disk usage % at which CRITICAL fires (triggers auto-prune)
    pub disk_crit_pct:     f64,

    /// Available RAM in MiB at which WARNING fires
    pub ram_warn_mib:      f64,
    /// Available RAM in MiB at which CRITICAL fires
    pub ram_crit_mib:      f64,

    /// CPU load average (1-min) ÷ nproc, WARNING
    pub cpu_warn_ratio:    f64,
    /// CPU load average (1-min) ÷ nproc, CRITICAL
    pub cpu_crit_ratio:    f64,

    /// PM2 restart count within the rolling window to declare a crash-loop
    pub crash_loop_count:  u32,
    /// Rolling window (seconds) for crash loop detection
    pub crash_loop_window: u64,

    /// Socket connect timeout in milliseconds
    pub socket_timeout_ms: u64,

    /// HTTP /health timeout in milliseconds
    pub http_timeout_ms:   u64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct HealingConfig {
    /// Whether to auto-restart vault-daemon on failure
    pub restart_daemon:      bool,
    /// Whether to auto-restart pwdnow (PM2) on failure
    pub restart_web:         bool,
    /// Whether to auto-restart nginx on failure
    pub restart_nginx:       bool,
    /// Max consecutive restart attempts before giving up and alerting
    pub max_restarts:        u32,
    /// Initial backoff seconds (doubles each attempt)
    pub backoff_initial_secs: u64,
    /// Whether to auto-prune old logs when disk is critical
    pub auto_prune_logs:     bool,
    /// Minimum log age in hours before pruning
    pub prune_log_age_hours: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct LogConfig {
    pub path:           PathBuf,
    /// Max log file size in MiB before rotation
    pub max_size_mib:   u64,
    /// Number of rotated files to keep
    pub keep_rotated:   u32,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct NotifyConfig {
    /// Send desktop notify-send alerts
    pub desktop:         bool,
    /// Optional webhook URL (empty = disabled)
    pub webhook_url:     String,
    /// Minimum severity to alert: "warn" | "critical"
    pub min_severity:    String,
    /// Cooldown between repeated alerts for the same issue (seconds)
    pub cooldown_secs:   u64,
}

// ── Defaults ──────────────────────────────────────────────────────────────────

impl Default for Config {
    fn default() -> Self {
        Self {
            poll_interval_secs: 10,
            paths:      PathsConfig::default(),
            thresholds: ThresholdConfig::default(),
            healing:    HealingConfig::default(),
            log:        LogConfig::default(),
            notify:     NotifyConfig::default(),
        }
    }
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            vault_socket:    PathBuf::from("/run/vault-daemon/vault.sock"),
            vault_db:        PathBuf::from("/var/lib/vault-daemon/vault.db"),
            vault_log_dir:   PathBuf::from("/var/log"),
            pm2_home:        PathBuf::from("/home/pwd-vm/.pm2"),
            web_port:        1234,
            health_endpoint: "/health".into(),
            tls_cert_paths:  vec![PathBuf::from("/etc/ssl/vault/cert.pem")],
            backup_dir:      PathBuf::from("/var/backups/vault-daemon"),
        }
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            disk_warn_pct:     85.0,
            disk_crit_pct:     92.0,
            ram_warn_mib:      400.0,
            ram_crit_mib:      150.0,
            cpu_warn_ratio:    0.8,
            cpu_crit_ratio:    1.2,
            crash_loop_count:  3,
            crash_loop_window: 300,
            socket_timeout_ms: 500,
            http_timeout_ms:   2000,
        }
    }
}

impl Default for HealingConfig {
    fn default() -> Self {
        Self {
            restart_daemon:       true,
            restart_web:          true,
            restart_nginx:        true,
            max_restarts:         5,
            backoff_initial_secs: 5,
            auto_prune_logs:      true,
            prune_log_age_hours:  24,
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            path:         PathBuf::from("/var/log/pwdnow-monitor.log"),
            max_size_mib: 50,
            keep_rotated: 3,
        }
    }
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            desktop:       true,
            webhook_url:   String::new(),
            min_severity:  "critical".into(),
            cooldown_secs: 300,
        }
    }
}

impl Config {
    /// Load config from `path`. Falls back to defaults for any missing keys.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&raw)?;
        Ok(cfg)
    }

    /// Load from path if it exists, otherwise return defaults.
    pub fn load_or_default(path: &std::path::Path) -> Self {
        if path.exists() {
            match Self::load(path) {
                Ok(c)  => c,
                Err(e) => {
                    eprintln!("[monitor] config parse error ({e}), using defaults");
                    Self::default()
                }
            }
        } else {
            Self::default()
        }
    }
}
