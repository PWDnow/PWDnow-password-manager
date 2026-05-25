//! Action engine — executes corrective actions in response to RiskEvents.
//! Uses exponential backoff to avoid restart storms.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::config::Config;
use crate::log::{Logger, Severity};
use crate::risk::{RiskAction, RiskEvent, RiskEngine};

/// State maintained between poll cycles for each service.
struct ServiceState {
    /// How many consecutive failed restart attempts
    attempts:        u32,
    /// When we last attempted a restart
    last_attempt_at: Option<Instant>,
    /// When the last alert was sent (for cooldown)
    last_alert_at:   Option<Instant>,
}

impl ServiceState {
    fn new() -> Self {
        Self {
            attempts:        0,
            last_attempt_at: None,
            last_alert_at:   None,
        }
    }

    /// Returns true if enough backoff time has passed to retry.
    fn can_retry(&self, initial_secs: u64, max_attempts: u32) -> bool {
        if self.attempts >= max_attempts {
            return false;
        }
        match self.last_attempt_at {
            None => true,
            Some(t) => {
                // Exponential backoff: initial * 2^(attempts-1)
                let backoff = initial_secs * (1u64 << self.attempts.min(7));
                t.elapsed() >= Duration::from_secs(backoff)
            }
        }
    }
}

pub struct ActionEngine {
    daemon: ServiceState,
    web:    ServiceState,
    nginx:  ServiceState,
    /// Per-component alert cooldown map
    alert_cooldowns: HashMap<String, Instant>,
}

impl ActionEngine {
    pub fn new() -> Self {
        Self {
            daemon:          ServiceState::new(),
            web:             ServiceState::new(),
            nginx:           ServiceState::new(),
            alert_cooldowns: HashMap::new(),
        }
    }

    /// Process all risk events from one poll cycle.
    pub fn process(
        &mut self,
        events:      &[RiskEvent],
        cfg:         &Config,
        log:         &Logger,
        risk_engine: &mut RiskEngine,
    ) {
        for event in events {
            match event.action {
                RiskAction::RestartDaemon => {
                    self.handle_restart_daemon(event, cfg, log, risk_engine);
                }
                RiskAction::RestartWeb => {
                    self.handle_restart_web(event, cfg, log, risk_engine);
                }
                RiskAction::RestartNginx => {
                    self.handle_restart_nginx(event, cfg, log, risk_engine);
                }
                RiskAction::PruneLogs => {
                    self.handle_prune_logs(event, cfg, log);
                }
                RiskAction::KillWebWorker => {
                    self.handle_kill_web_worker(event, cfg, log);
                }
                RiskAction::Alert => {
                    self.handle_alert(event, cfg, log);
                }
                RiskAction::None => {}
            }
        }

        // Reset service attempt counters when services come back healthy
        // (done by risk engine, but also reset our local state to avoid stale counters)
        if risk_engine.daemon_restart_attempts == 0 && self.daemon.attempts > 0 {
            info!("vault-daemon recovered — resetting restart counter");
            self.daemon = ServiceState::new();
        }
        if risk_engine.web_restart_attempts == 0 && self.web.attempts > 0 {
            info!("pwdnow web recovered — resetting restart counter");
            self.web = ServiceState::new();
        }
    }

    fn handle_restart_daemon(
        &mut self,
        event:       &RiskEvent,
        cfg:         &Config,
        log:         &Logger,
        risk_engine: &mut RiskEngine,
    ) {
        let h = &cfg.healing;
        if !self.daemon.can_retry(h.backoff_initial_secs, h.max_restarts) {
            warn!("vault-daemon: max restart attempts ({}) reached, switching to alert only", h.max_restarts);
            self.send_notify(&event.component, &event.message, Severity::Emergency, cfg);
            log.emergency("vault-daemon", &format!(
                "{}. Max restarts reached — manual intervention required.", event.message
            ));
            return;
        }

        self.daemon.attempts += 1;
        self.daemon.last_attempt_at = Some(Instant::now());
        risk_engine.daemon_restart_attempts = self.daemon.attempts;

        let attempt = self.daemon.attempts;
        info!("Attempting vault-daemon restart (attempt {attempt}/{})...", h.max_restarts);

        let result = systemctl_restart("vault-daemon");
        if result {
            log.recovery(
                "vault-daemon",
                &format!("vault-daemon restarted successfully (attempt {attempt})"),
                "systemctl restart vault-daemon",
            );
            self.send_notify("vault-daemon", "vault-daemon was down and has been restarted", Severity::Warn, cfg);
        } else {
            log.critical(
                "vault-daemon",
                &format!("vault-daemon restart FAILED (attempt {attempt})"),
                attempt as f64,
                "attempt",
                None,
            );
            self.send_notify("vault-daemon", "vault-daemon restart FAILED", Severity::Critical, cfg);
        }
    }

    fn handle_restart_web(
        &mut self,
        event:       &RiskEvent,
        cfg:         &Config,
        log:         &Logger,
        risk_engine: &mut RiskEngine,
    ) {
        let h = &cfg.healing;
        if !self.web.can_retry(h.backoff_initial_secs, h.max_restarts) {
            self.send_notify(&event.component, &event.message, Severity::Emergency, cfg);
            log.emergency("pwdnow-web", &format!(
                "{}. Max restarts reached — manual intervention required.", event.message
            ));
            return;
        }

        self.web.attempts += 1;
        self.web.last_attempt_at = Some(Instant::now());
        risk_engine.web_restart_attempts = self.web.attempts;

        let attempt = self.web.attempts;
        info!("Attempting pwdnow PM2 restart (attempt {attempt}/{})...", h.max_restarts);

        let result = pm2_restart("pwdnow");
        if result {
            log.recovery(
                "pwdnow-web",
                &format!("PM2 pwdnow restarted successfully (attempt {attempt})"),
                "pm2 restart pwdnow",
            );
            self.send_notify("pwdnow-web", "PM2 pwdnow was down and has been restarted", Severity::Warn, cfg);
        } else {
            log.critical(
                "pwdnow-web",
                &format!("PM2 pwdnow restart FAILED (attempt {attempt})"),
                attempt as f64,
                "attempt",
                None,
            );
            self.send_notify("pwdnow-web", "PM2 pwdnow restart FAILED", Severity::Critical, cfg);
        }
    }

    fn handle_restart_nginx(
        &mut self,
        event:       &RiskEvent,
        cfg:         &Config,
        log:         &Logger,
        risk_engine: &mut RiskEngine,
    ) {
        let h = &cfg.healing;
        if !self.nginx.can_retry(h.backoff_initial_secs, h.max_restarts) {
            log.emergency("nginx", &format!(
                "{}. Max restarts reached.", event.message
            ));
            return;
        }

        self.nginx.attempts += 1;
        self.nginx.last_attempt_at = Some(Instant::now());
        risk_engine.nginx_restart_attempts = self.nginx.attempts;

        let result = systemctl_restart("nginx");
        if result {
            log.recovery("nginx", "nginx restarted successfully", "systemctl restart nginx");
        } else {
            log.critical("nginx", "nginx restart FAILED", self.nginx.attempts as f64, "attempt", None);
        }
    }

    fn handle_prune_logs(&self, event: &RiskEvent, cfg: &Config, log: &Logger) {
        warn!("Disk critical — pruning old log files to free space");

        // 1. Prune PM2 logs in the web directory
        let pm2_log_dir = cfg.paths.pm2_home.join("logs");
        if pm2_log_dir.exists() {
            prune_old_files(&pm2_log_dir, cfg.healing.prune_log_age_hours);
        }

        // 2. Prune system logs in /var/log older than configured hours
        prune_old_files(
            std::path::Path::new("/var/log"),
            cfg.healing.prune_log_age_hours,
        );

        // 3. Prune monitor's own log
        log.prune_self();

        // 4. Log the action
        log.recovery(
            "disk",
            &format!("Disk pruning completed in response to: {}", event.message),
            "prune old logs",
        );

        self.send_notify("disk", "Disk critical — old logs pruned automatically", Severity::Critical, cfg);
    }

    fn handle_kill_web_worker(&self, event: &RiskEvent, cfg: &Config, log: &Logger) {
        warn!("RAM critical — requesting PM2 to reduce worker count");

        // Ask PM2 to scale down by 1 worker
        let result = std::process::Command::new("pm2")
            .args(["scale", "pwdnow", "-1"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if result {
            log.recovery("ram", "Scaled down PM2 worker to free RAM", "pm2 scale pwdnow -1");
        } else {
            log.critical("ram", "Failed to scale down PM2 worker", event.value.unwrap_or(0.0), "MiB", None);
        }

        self.send_notify("ram", "RAM critical — scaled down web workers to recover memory", Severity::Critical, cfg);
    }

    fn handle_alert(&mut self, event: &RiskEvent, cfg: &Config, log: &Logger) {
        let cooldown = Duration::from_secs(cfg.notify.cooldown_secs);
        let now = Instant::now();
        let key = format!("{}:{:?}", event.component, event.severity);

        if let Some(last) = self.alert_cooldowns.get(&key) {
            if now.duration_since(*last) < cooldown {
                return; // Still in cooldown for this component+severity
            }
        }
        self.alert_cooldowns.insert(key, now);

        let sev = match event.severity {
            crate::risk::Severity::Warn      => Severity::Warn,
            crate::risk::Severity::Critical  => Severity::Critical,
            crate::risk::Severity::Emergency => Severity::Emergency,
        };

        log.write(
            sev,
            &event.component,
            &event.message,
            event.value,
            event.unit.as_deref(),
            event.eta_secs,
            None,
        );

        // Only send desktop notification for critical+ by default
        let should_notify = match event.severity {
            crate::risk::Severity::Warn      => cfg.notify.min_severity == "warn",
            crate::risk::Severity::Critical
            | crate::risk::Severity::Emergency => true,
        };

        if should_notify {
            self.send_notify(&event.component, &event.message, sev, cfg);
        }
    }

    fn send_notify(&self, component: &str, message: &str, severity: Severity, cfg: &Config) {
        let urgency = match severity {
            Severity::Info | Severity::Recovery | Severity::Warn => "normal",
            Severity::Critical | Severity::Emergency             => "critical",
        };
        let icon = match severity {
            Severity::Info | Severity::Recovery => "dialog-information",
            Severity::Warn                      => "dialog-warning",
            Severity::Critical | Severity::Emergency => "dialog-error",
        };
        let title = format!("PWDnow [{component}]");

        if cfg.notify.desktop {
            let _ = std::process::Command::new("notify-send")
                .args([
                    "--urgency", urgency,
                    "--icon",    icon,
                    "--app-name", "PWDnowMonitoringENV",
                    &title,
                    message,
                ])
                .output();
        }

        // Webhook (if configured)
        if !cfg.notify.webhook_url.is_empty() {
            self.send_webhook(&cfg.notify.webhook_url, &title, message, severity);
        }
    }

    fn send_webhook(&self, url: &str, title: &str, message: &str, severity: Severity) {
        // Minimal webhook POST via raw TCP — no HTTP client dependency.
        // Only supports http:// webhooks (https requires TLS which adds weight).
        // For production TLS webhooks, route through a local proxy.
        let body = serde_json::json!({
            "text": format!("🚨 *{}*: {}", title, message),
            "severity": format!("{severity:?}"),
            "service": "PWDnowMonitoringENV"
        })
        .to_string();

        // Fire and forget via OS command to curl (avoid building a full HTTP client)
        let _ = std::process::Command::new("curl")
            .args([
                "--silent",
                "--max-time", "5",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", &body,
                url,
            ])
            .spawn(); // non-blocking
    }
}

// ── Helper functions ──────────────────────────────────────────────────────────

fn systemctl_restart(service: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["restart", service])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn pm2_restart(app: &str) -> bool {
    std::process::Command::new("pm2")
        .args(["restart", app])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Delete log files in `dir` older than `age_hours`. Non-recursive, targets
/// only files (*.log, *.out, *.err) to avoid accidentally deleting data.
fn prune_old_files(dir: &std::path::Path, age_hours: u64) {
    let cutoff = std::time::SystemTime::now()
        - Duration::from_secs(age_hours * 3600);

    let entries = match std::fs::read_dir(dir) {
        Ok(e)  => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "log" | "out" | "err") { continue; }

        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                if modified < cutoff {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
}
