//! Structured JSON logger with automatic size-based log rotation.
//! All output goes to both the log file AND systemd journal (via tracing).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;
use serde::Serialize;
use tracing::{error, info, warn};

use crate::config::LogConfig;

/// Severity levels for log entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Warn,
    Critical,
    Recovery,
    Emergency,
}

/// A single structured log entry written as newline-delimited JSON.
#[derive(Debug, Serialize)]
struct LogEntry<'a> {
    ts:        String,
    severity:  Severity,
    component: &'a str,
    message:   &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value:     Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unit:      Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eta_secs:  Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action:    Option<&'a str>,
}

pub struct Logger {
    path:         PathBuf,
    max_bytes:    u64,
    keep_rotated: u32,
    file:         Mutex<File>,
}

impl Logger {
    pub fn new(cfg: &LogConfig) -> anyhow::Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = cfg.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.path)?;

        Ok(Self {
            path:         cfg.path.clone(),
            max_bytes:    cfg.max_size_mib * 1024 * 1024,
            keep_rotated: cfg.keep_rotated,
            file:         Mutex::new(file),
        })
    }

    /// Write a log entry. Rotates the file if it exceeds `max_bytes`.
    pub fn write(
        &self,
        severity:  Severity,
        component: &str,
        message:   &str,
        value:     Option<f64>,
        unit:      Option<&str>,
        eta_secs:  Option<i64>,
        action:    Option<&str>,
    ) {
        // Mirror to tracing (goes to journal)
        match severity {
            Severity::Info | Severity::Recovery =>
                info!(component, message, ?value, ?action),
            Severity::Warn =>
                warn!(component, message, ?value, ?action),
            Severity::Critical | Severity::Emergency =>
                error!(component, message, ?value, ?action),
        }

        let entry = LogEntry {
            ts: Utc::now().to_rfc3339(),
            severity,
            component,
            message,
            value,
            unit,
            eta_secs,
            action,
        };

        let line = match serde_json::to_string(&entry) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[monitor] log serialization error: {e}");
                return;
            }
        };

        let mut guard = match self.file.lock() {
            Ok(g) => g,
            Err(_) => return,
        };

        // Check size and rotate if needed before writing
        if let Ok(meta) = guard.metadata() {
            if meta.len() >= self.max_bytes {
                drop(guard);
                self.rotate();
                guard = match self.file.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                // Reopen after rotation
                if let Ok(f) = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)
                {
                    *guard = f;
                }
            }
        }

        let _ = writeln!(*guard, "{line}");
    }

    fn rotate(&self) {
        // Shift existing rotated files: .3 → drop, .2 → .3, .1 → .2, base → .1
        for i in (1..self.keep_rotated).rev() {
            let from = rotated_path(&self.path, i);
            let to   = rotated_path(&self.path, i + 1);
            if from.exists() {
                let _ = fs::rename(&from, &to);
            }
        }
        let rotated = rotated_path(&self.path, 1);
        let _ = fs::rename(&self.path, &rotated);

        // Remove any rotated files beyond keep_rotated
        for i in (self.keep_rotated + 1)..=(self.keep_rotated + 5) {
            let old = rotated_path(&self.path, i);
            if old.exists() {
                let _ = fs::remove_file(&old);
            } else {
                break;
            }
        }
    }

    // ── Convenience helpers ────────────────────────────────────────────────────

    pub fn info(&self, component: &str, msg: &str) {
        self.write(Severity::Info, component, msg, None, None, None, None);
    }

    pub fn warn_metric(&self, component: &str, msg: &str, val: f64, unit: &str, eta: Option<i64>) {
        self.write(Severity::Warn, component, msg, Some(val), Some(unit), eta, None);
    }

    pub fn critical(&self, component: &str, msg: &str, val: f64, unit: &str, eta: Option<i64>) {
        self.write(Severity::Critical, component, msg, Some(val), Some(unit), eta, None);
    }

    pub fn recovery(&self, component: &str, msg: &str, action: &str) {
        self.write(Severity::Recovery, component, msg, None, None, None, Some(action));
    }

    pub fn emergency(&self, component: &str, msg: &str) {
        self.write(Severity::Emergency, component, msg, None, None, None, None);
    }

    /// Called by the auto-prune action to free space on the log file itself.
    pub fn prune_self(&self) {
        let _ = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path);
        self.info("log", "log file pruned due to critical disk pressure");
    }
}

fn rotated_path(base: &Path, n: u32) -> PathBuf {
    let mut p = base.to_path_buf();
    let name = base.file_name().unwrap_or_default().to_string_lossy();
    p.set_file_name(format!("{name}.{n}"));
    p
}
