//! Risk engine — evaluates a Snapshot against configured thresholds,
//! maintains rolling ring-buffers for trend analysis, and produces
//! a list of RiskEvents for the action engine to act on.

use std::collections::VecDeque;

use crate::config::Config;
use crate::collector::Snapshot;

/// Maximum ring-buffer size: 60 samples × 10s = 10 min of history.
const RING_SIZE: usize = 60;

/// Severity of a risk event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warn,
    Critical,
    Emergency,
}

/// A single risk event produced by the risk engine.
#[derive(Debug, Clone)]
pub struct RiskEvent {
    pub severity:  Severity,
    pub component: String,
    pub message:   String,
    pub value:     Option<f64>,
    pub unit:      Option<String>,
    /// Predicted seconds until a critical threshold is breached (None = already past it)
    pub eta_secs:  Option<i64>,
    /// Suggested corrective action
    pub action:    RiskAction,
}

/// What the action engine should do in response to a RiskEvent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskAction {
    RestartDaemon,
    RestartWeb,
    RestartNginx,
    PruneLogs,
    KillWebWorker,
    Alert,
    None,
}

/// Stateful risk engine. Call `evaluate()` every poll cycle.
pub struct RiskEngine {
    /// Sliding window of disk_used_pct samples
    disk_ring:     RingBuffer,
    /// Sliding window of ram_available_mib samples
    ram_ring:      RingBuffer,
    /// Sliding window of cpu_usage_pct samples
    cpu_ring:      RingBuffer,
    /// PM2 restart count history for crash-loop detection
    restart_ring:  VecDeque<(i64, u32)>, // (ts_secs, restart_count)
    /// Track how many times we've tried to restart each service (for backoff)
    pub daemon_restart_attempts: u32,
    pub web_restart_attempts:    u32,
    pub nginx_restart_attempts:  u32,
    /// Timestamp of last recovery (used to reset attempt counter)
    daemon_last_ok_ts:  i64,
    web_last_ok_ts:     i64,
    nginx_last_ok_ts:   i64,
}

impl RiskEngine {
    pub fn new() -> Self {
        Self {
            disk_ring:    RingBuffer::new(RING_SIZE),
            ram_ring:     RingBuffer::new(RING_SIZE),
            cpu_ring:     RingBuffer::new(RING_SIZE),
            restart_ring: VecDeque::with_capacity(RING_SIZE),
            daemon_restart_attempts: 0,
            web_restart_attempts:    0,
            nginx_restart_attempts:  0,
            daemon_last_ok_ts:  0,
            web_last_ok_ts:     0,
            nginx_last_ok_ts:   0,
        }
    }

    /// Feed a new snapshot and return zero or more risk events.
    pub fn evaluate(&mut self, snap: &Snapshot, cfg: &Config) -> Vec<RiskEvent> {
        let mut events = Vec::new();
        let now = snap.ts_secs;
        let _poll_secs = cfg.poll_interval_secs as i64;

        // ── Update ring buffers ───────────────────────────────────────────────
        self.disk_ring.push(snap.ts_secs as f64, snap.disk_used_pct);
        self.ram_ring.push(snap.ts_secs as f64, snap.ram_available_mib);
        self.cpu_ring.push(snap.ts_secs as f64, snap.cpu_usage_pct);

        // Track PM2 restarts with timestamps for crash-loop detection
        self.restart_ring.push_back((now, snap.web_pm2_restarts));
        if self.restart_ring.len() > RING_SIZE {
            self.restart_ring.pop_front();
        }

        let t = &cfg.thresholds;
        let h = &cfg.healing;

        // ── vault-daemon health ───────────────────────────────────────────────
        let daemon_ok = snap.daemon_active && snap.daemon_socket_ok;
        if daemon_ok {
            // Reset attempt counter after successful recovery
            if self.daemon_restart_attempts > 0 {
                self.daemon_restart_attempts = 0;
            }
            self.daemon_last_ok_ts = now;
        } else {
            let action = if h.restart_daemon && self.daemon_restart_attempts < h.max_restarts {
                RiskAction::RestartDaemon
            } else {
                RiskAction::Alert
            };
            events.push(RiskEvent {
                severity:  Severity::Critical,
                component: "vault-daemon".into(),
                message:   format!(
                    "vault-daemon is DOWN (systemctl={}, socket={})",
                    snap.daemon_active, snap.daemon_socket_ok
                ),
                value:     None,
                unit:      None,
                eta_secs:  None,
                action,
            });
        }

        // ── Socket latency ────────────────────────────────────────────────────
        if snap.daemon_socket_ok && snap.daemon_socket_ms > 500.0 {
            events.push(RiskEvent {
                severity:  Severity::Warn,
                component: "vault-daemon-latency".into(),
                message:   "vault-daemon socket response is slow".into(),
                value:     Some(snap.daemon_socket_ms),
                unit:      Some("ms".into()),
                eta_secs:  None,
                action:    RiskAction::Alert,
            });
        }

        // ── PM2 / web health ──────────────────────────────────────────────────
        let web_ok = snap.web_pm2_online && snap.web_port_open;
        if web_ok {
            if self.web_restart_attempts > 0 {
                self.web_restart_attempts = 0;
            }
            self.web_last_ok_ts = now;
        } else {
            let action = if h.restart_web && self.web_restart_attempts < h.max_restarts {
                RiskAction::RestartWeb
            } else {
                RiskAction::Alert
            };
            events.push(RiskEvent {
                severity:  Severity::Critical,
                component: "pwdnow-web".into(),
                message:   format!(
                    "pwdnow web is DOWN (pm2={}, port={})",
                    snap.web_pm2_online, snap.web_port_open
                ),
                value:     None,
                unit:      None,
                eta_secs:  None,
                action,
            });
        }

        // ── Crash loop detection ──────────────────────────────────────────────
        let window_start = now - cfg.thresholds.crash_loop_window as i64;
        let restarts_in_window = self.restart_ring.iter()
            .filter(|(ts, _)| *ts >= window_start)
            .count();
        if restarts_in_window as u32 >= t.crash_loop_count {
            events.push(RiskEvent {
                severity:  Severity::Critical,
                component: "pwdnow-web".into(),
                message:   format!(
                    "PM2 crash loop detected: {} restarts in {}s window",
                    restarts_in_window, cfg.thresholds.crash_loop_window
                ),
                value:     Some(restarts_in_window as f64),
                unit:      Some("restarts".into()),
                eta_secs:  None,
                action:    RiskAction::Alert, // Don't blindly restart a looping process
            });
        }

        // ── /health check ─────────────────────────────────────────────────────
        if snap.web_port_open && !snap.web_health_ok {
            events.push(RiskEvent {
                severity:  Severity::Warn,
                component: "pwdnow-web".into(),
                message:   "GET /health did not return 200".into(),
                value:     Some(snap.web_health_ms),
                unit:      Some("ms".into()),
                eta_secs:  None,
                action:    RiskAction::Alert,
            });
        }

        // ── nginx health ──────────────────────────────────────────────────────
        // nginx is optional (may not be configured), so only warn if it's installed but down
        if !snap.nginx_active && snap.nginx_port_ok {
            // Port is up but systemctl says inactive — something else is serving, that's OK
        } else if snap.nginx_active && !snap.nginx_port_ok {
            let action = if h.restart_nginx && self.nginx_restart_attempts < h.max_restarts {
                RiskAction::RestartNginx
            } else {
                RiskAction::Alert
            };
            events.push(RiskEvent {
                severity:  Severity::Critical,
                component: "nginx".into(),
                message:   "nginx is active but not listening on port 80/443".into(),
                value:     None,
                unit:      None,
                eta_secs:  None,
                action,
            });
        }

        // ── Disk space ────────────────────────────────────────────────────────
        let disk_pct  = snap.disk_used_pct;
        let disk_rate = self.disk_ring.trend_per_second(); // % per second

        if disk_pct >= t.disk_crit_pct {
            // Predict ETA to 95% (hard failure)
            let eta = eta_to_threshold(&self.disk_ring, 95.0);
            events.push(RiskEvent {
                severity:  Severity::Critical,
                component: "disk".into(),
                message:   format!("Disk usage is CRITICAL: {disk_pct:.1}%"),
                value:     Some(disk_pct),
                unit:      Some("%".into()),
                eta_secs:  eta,
                action:    if h.auto_prune_logs { RiskAction::PruneLogs } else { RiskAction::Alert },
            });
        } else if disk_pct >= t.disk_warn_pct {
            let eta = eta_to_threshold(&self.disk_ring, t.disk_crit_pct);
            events.push(RiskEvent {
                severity:  Severity::Warn,
                component: "disk".into(),
                message:   format!("Disk usage WARNING: {disk_pct:.1}%"),
                value:     Some(disk_pct),
                unit:      Some("%".into()),
                eta_secs:  eta,
                action:    RiskAction::Alert,
            });
        } else if disk_rate > 0.0 {
            // Not at warning yet, but predict when it will hit warning threshold
            let eta = eta_to_threshold(&self.disk_ring, t.disk_warn_pct);
            if let Some(secs) = eta {
                if secs < 3600 * 4 {
                    // Less than 4 hours to warning — pre-emptive alert
                    events.push(RiskEvent {
                        severity:  Severity::Warn,
                        component: "disk".into(),
                        message:   format!("Disk trending toward warning in ~{}min", secs / 60),
                        value:     Some(disk_pct),
                        unit:      Some("%".into()),
                        eta_secs:  Some(secs),
                        action:    RiskAction::Alert,
                    });
                }
            }
        }

        // ── RAM ───────────────────────────────────────────────────────────────
        let ram_mib = snap.ram_available_mib;

        if ram_mib <= t.ram_crit_mib {
            let eta = eta_to_threshold_falling(&self.ram_ring, 50.0);
            events.push(RiskEvent {
                severity:  Severity::Critical,
                component: "ram".into(),
                message:   format!("RAM available CRITICAL: {ram_mib:.0} MiB"),
                value:     Some(ram_mib),
                unit:      Some("MiB".into()),
                eta_secs:  eta,
                action:    RiskAction::KillWebWorker,
            });
        } else if ram_mib <= t.ram_warn_mib {
            let eta = eta_to_threshold_falling(&self.ram_ring, t.ram_crit_mib);
            events.push(RiskEvent {
                severity:  Severity::Warn,
                component: "ram".into(),
                message:   format!("RAM available WARNING: {ram_mib:.0} MiB"),
                value:     Some(ram_mib),
                unit:      Some("MiB".into()),
                eta_secs:  eta,
                action:    RiskAction::Alert,
            });
        }

        // ── CPU ───────────────────────────────────────────────────────────────
        let nproc = num_cpus();
        let load  = snap.load_avg_1;
        let ratio = if nproc > 0 { load / nproc as f64 } else { 0.0 };

        if ratio >= t.cpu_crit_ratio {
            events.push(RiskEvent {
                severity:  Severity::Critical,
                component: "cpu".into(),
                message:   format!("CPU load critical: {load:.2} ({ratio:.0}% of capacity)"),
                value:     Some(load),
                unit:      Some("load".into()),
                eta_secs:  None,
                action:    RiskAction::Alert,
            });
        } else if ratio >= t.cpu_warn_ratio {
            events.push(RiskEvent {
                severity:  Severity::Warn,
                component: "cpu".into(),
                message:   format!("CPU load warning: {load:.2} ({:.0}% of capacity)", ratio * 100.0),
                value:     Some(load),
                unit:      Some("load".into()),
                eta_secs:  None,
                action:    RiskAction::Alert,
            });
        }

        events
    }
}

// ── Ring buffer with linear regression ───────────────────────────────────────

pub struct RingBuffer {
    data:     VecDeque<(f64, f64)>, // (timestamp_secs, value)
    capacity: usize,
}

impl RingBuffer {
    pub fn new(cap: usize) -> Self {
        Self { data: VecDeque::with_capacity(cap), capacity: cap }
    }

    pub fn push(&mut self, ts: f64, value: f64) {
        if self.data.len() >= self.capacity {
            self.data.pop_front();
        }
        self.data.push_back((ts, value));
    }

    pub fn len(&self) -> usize { self.data.len() }

    /// Slope of the linear regression (units/second). Positive = rising.
    pub fn trend_per_second(&self) -> f64 {
        if self.data.len() < 2 { return 0.0; }
        linear_regression_slope(&self.data)
    }

    /// Latest value.
    pub fn last(&self) -> Option<f64> { self.data.back().map(|(_, v)| *v) }
}

/// Ordinary least squares slope (β₁ = Σ(x-x̄)(y-ȳ) / Σ(x-x̄)²).
fn linear_regression_slope(data: &VecDeque<(f64, f64)>) -> f64 {
    let n = data.len() as f64;
    let (sx, sy) = data.iter().fold((0.0f64, 0.0f64), |(ax, ay), (x, y)| (ax + x, ay + y));
    let (mx, my) = (sx / n, sy / n);

    let (num, den) = data.iter().fold((0.0f64, 0.0f64), |(num, den), (x, y)| {
        let dx = x - mx;
        (num + dx * (y - my), den + dx * dx)
    });

    if den.abs() < 1e-10 { 0.0 } else { num / den }
}

/// Estimate seconds until `ring` values reach `threshold` (rising trend).
fn eta_to_threshold(ring: &RingBuffer, threshold: f64) -> Option<i64> {
    let slope = ring.trend_per_second();
    if slope <= 0.0 { return None; } // Not rising
    let current = ring.last()?;
    if current >= threshold { return Some(0); }
    Some(((threshold - current) / slope) as i64)
}

/// Estimate seconds until `ring` values fall to `threshold` (falling trend).
fn eta_to_threshold_falling(ring: &RingBuffer, threshold: f64) -> Option<i64> {
    let slope = ring.trend_per_second();
    if slope >= 0.0 { return None; } // Not falling
    let current = ring.last()?;
    if current <= threshold { return Some(0); }
    Some(((current - threshold) / (-slope)) as i64)
}

fn num_cpus() -> usize {
    // Read from /proc/cpuinfo — count "processor" lines
    std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count()
        .max(1)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_regression_flat() {
        let mut ring = RingBuffer::new(10);
        for i in 0..10 {
            ring.push(i as f64, 50.0);
        }
        assert!((ring.trend_per_second()).abs() < 1e-6);
    }

    #[test]
    fn test_linear_regression_rising() {
        let mut ring = RingBuffer::new(10);
        // disk rising 0.1% per second
        for i in 0..10 {
            ring.push(i as f64 * 10.0, 80.0 + i as f64 * 1.0);
        }
        let slope = ring.trend_per_second();
        assert!(slope > 0.0, "slope should be positive: {slope}");
    }

    #[test]
    fn test_eta_to_threshold() {
        let mut ring = RingBuffer::new(10);
        // Rising 0.1% per second, starting at 85% → ETA to 92% should be ~70s
        for i in 0..10 {
            ring.push(i as f64 * 10.0, 85.0 + i as f64 * 0.1);
        }
        let eta = eta_to_threshold(&ring, 92.0);
        assert!(eta.is_some());
        assert!(eta.unwrap() > 0);
    }

    #[test]
    fn test_risk_engine_disk_critical() {
        let cfg = Config::default();
        let mut engine = RiskEngine::new();

        // Feed 60 samples of rising disk usage to fill the ring
        for i in 0..60 {
            let mut snap = Snapshot::default();
            snap.ts_secs        = i * 10;
            snap.disk_used_pct  = 93.0 + i as f64 * 0.01;
            snap.ram_available_mib = 500.0;
            snap.daemon_active    = true;
            snap.daemon_socket_ok = true;
            snap.web_pm2_online   = true;
            snap.web_port_open    = true;
            snap.web_health_ok    = true;

            let events = engine.evaluate(&snap, &cfg);
            if i == 59 {
                let disk_evt = events.iter().find(|e| e.component == "disk");
                assert!(disk_evt.is_some(), "should have disk critical event");
                assert_eq!(disk_evt.unwrap().severity, Severity::Critical);
            }
        }
    }

    #[test]
    fn test_risk_engine_daemon_down() {
        let cfg = Config::default();
        let mut engine = RiskEngine::new();
        let mut snap = Snapshot::default();
        snap.ts_secs         = 1000;
        snap.daemon_active   = false;
        snap.daemon_socket_ok = false;
        snap.ram_available_mib = 500.0;
        snap.disk_used_pct   = 50.0;
        snap.web_pm2_online  = true;
        snap.web_port_open   = true;
        snap.web_health_ok   = true;

        let events = engine.evaluate(&snap, &cfg);
        let daemon_evt = events.iter().find(|e| e.component == "vault-daemon");
        assert!(daemon_evt.is_some());
        assert_eq!(daemon_evt.unwrap().action, RiskAction::RestartDaemon);
    }
}
