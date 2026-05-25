//! PWDnowMonitoringENV — main entry point.
//!
//! Lightweight Rust watchdog for the PWDnow password manager.
//! Targets 99.99% SLA via predictive monitoring, auto-healing,
//! and integration with systemd for boot-time auto-start.

mod action;
mod collector;
mod config;
mod leak;
mod log;
mod risk;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use collector::{
    cert::CertCollector, daemon::DaemonCollector, system::SystemCollector,
    web::WebCollector, Snapshot,
};
use tokio::signal;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use action::ActionEngine;
use config::Config;
use log::Logger;
use risk::RiskEngine;

const DEFAULT_CONFIG_PATH: &str = "/etc/pwdnow-monitor.toml";
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// SLA P1: window length (36 samples × poll_interval_secs) — used only in
/// the leak detector's log message so the duration is meaningful to ops.
const WINDOW_SAMPLES_SECS: u64 = 36 * 10;

#[tokio::main]
async fn main() {
    // ── Logging ───────────────────────────────────────────────────────────────
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .compact()
        .init();

    info!("PWDnowMonitoringENV v{VERSION} starting");

    // ── Config ────────────────────────────────────────────────────────────────
    let config_path = parse_config_arg()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));

    // SLA S2: config behind an RwLock so SIGHUP can reload without restart.
    // Hot-reloadable: thresholds + healing + notify + cert paths. Cold-only:
    // log path (would orphan the open fd) and poll_interval_secs (would need
    // to rebuild the ticker).
    let cfg_initial = Config::load_or_default(&config_path);
    info!(
        poll_secs     = cfg_initial.poll_interval_secs,
        disk_warn_pct = cfg_initial.thresholds.disk_warn_pct,
        ram_warn_mib  = cfg_initial.thresholds.ram_warn_mib,
        "Configuration loaded"
    );

    // ── Structured file logger ────────────────────────────────────────────────
    let logger: Arc<Logger> = match Logger::new(&cfg_initial.log) {
        Ok(l)  => Arc::new(l),
        Err(e) => {
            error!("Failed to open log file {}: {e}", cfg_initial.log.path.display());
            // Fall back gracefully — journal still works
            eprintln!("[monitor] WARNING: could not open log file, using journal only");
            // Create a /tmp fallback
            let mut fallback_cfg = cfg_initial.log.clone();
            fallback_cfg.path = PathBuf::from("/tmp/pwdnow-monitor.log");
            match Logger::new(&fallback_cfg) {
                Ok(l)  => Arc::new(l),
                Err(e2) => {
                    eprintln!("[monitor] FATAL: cannot open any log file: {e2}");
                    std::process::exit(1);
                }
            }
        }
    };

    let cfg_shared: Arc<RwLock<Config>> = Arc::new(RwLock::new(cfg_initial));

    // ── Collectors ────────────────────────────────────────────────────────────
    let mut sys_collector  = SystemCollector::new();
    let daemon_collector   = DaemonCollector::new();
    let web_collector      = WebCollector::new();
    let cert_collector     = CertCollector::new();

    // ── Engines ───────────────────────────────────────────────────────────────
    let mut risk_engine   = RiskEngine::new();
    let mut action_engine = ActionEngine::new();

    // ── systemd readiness notification ────────────────────────────────────────
    #[cfg(target_os = "linux")]
    {
        let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);
    }

    // ── Watchdog heartbeat to systemd ─────────────────────────────────────────
    #[cfg(target_os = "linux")]
    if let Ok(usec_str) = std::env::var("WATCHDOG_USEC") {
        if let Ok(usec) = usec_str.parse::<u64>() {
            let interval = Duration::from_micros(usec / 3);
            tokio::spawn(async move {
                let mut ticker = time::interval(interval);
                loop {
                    ticker.tick().await;
                    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
                }
            });
        }
    }

    {
        let cfg = cfg_shared.read().await;
        logger.info("monitor", &format!("PWDnowMonitoringENV v{VERSION} started — poll every {}s", cfg.poll_interval_secs));
    }

    // ── SIGHUP → live config reload (SLA S2) ──────────────────────────────────
    #[cfg(unix)]
    {
        let cfg_for_hup = Arc::clone(&cfg_shared);
        let path_for_hup = config_path.clone();
        let logger_for_hup = Arc::clone(&logger);
        tokio::spawn(async move {
            let mut sighup = match signal::unix::signal(signal::unix::SignalKind::hangup()) {
                Ok(s)  => s,
                Err(e) => { warn!("cannot install SIGHUP handler: {e}"); return; }
            };
            while sighup.recv().await.is_some() {
                let new_cfg = Config::load_or_default(&path_for_hup);
                let mut guard = cfg_for_hup.write().await;
                // Hot-reloadable subset only.
                guard.thresholds = new_cfg.thresholds.clone();
                guard.healing    = new_cfg.healing.clone();
                guard.notify     = new_cfg.notify.clone();
                guard.paths.tls_cert_paths = new_cfg.paths.tls_cert_paths.clone();
                guard.paths.backup_dir     = new_cfg.paths.backup_dir.clone();
                info!("SIGHUP — config reloaded (thresholds/healing/notify/cert_paths)");
                logger_for_hup.info("monitor", "Config reloaded via SIGHUP");
            }
        });
    }

    // ── Main poll loop ────────────────────────────────────────────────────────
    let poll_interval = {
        let cfg = cfg_shared.read().await;
        Duration::from_secs(cfg.poll_interval_secs)
    };
    let mut ticker = time::interval(poll_interval);
    // Cert collector is heavy-ish (forks openssl); run it once per day, not every poll.
    let mut cert_ticker = time::interval(Duration::from_secs(86_400));
    // Skip the first immediate tick — we want the first cert check to happen
    // ~60 s after start so logs aren't a wall of "startup noise".
    cert_ticker.tick().await;

    // SLA P1: per-tier leak detectors. Currently only the web tier RSS is
    // collected (via /proc/<node-pid>); add daemon RSS when the collector
    // grows that field. We instantiate per-tier to avoid cross-talk.
    let mut leak_web = leak::LeakDetector::new();

    loop {
        let cfg_snapshot = { cfg_shared.read().await.clone() };
        tokio::select! {
            _ = ticker.tick() => {
                let snap = poll_cycle(
                    &mut sys_collector,
                    &daemon_collector,
                    &web_collector,
                    &mut risk_engine,
                    &mut action_engine,
                    &cfg_snapshot,
                    &logger,
                ).await;
                // SLA P1: feed RAM used (= total - available) into the leak
                // detector. Coarse proxy for process RSS, but catches the
                // pathology that matters: monotonic host-memory growth. Per-
                // process RSS breakdown is in the §4 backlog.
                let used_bytes = ((snap.ram_total_mib - snap.ram_available_mib).max(0.0)
                                  * 1024.0 * 1024.0) as u64;
                if let Some((from, to)) = leak_web.observe(used_bytes) {
                    let grew_mib = (to.saturating_sub(from)) / 1_048_576;
                    logger.critical(
                        "leak",
                        &format!("monotonic RAM growth detected: {grew_mib} MiB over ~{}s — possible leak",
                                 WINDOW_SAMPLES_SECS),
                        grew_mib as f64, "MiB", None,
                    );
                }
            }
            _ = cert_ticker.tick() => {
                // Fold cert collection into the next snapshot — we evaluate
                // its event on the next regular tick. Done this way so cert
                // alerts share the same dedupe/cooldown path as everything else.
                let mut snap = Snapshot::with_ts(Utc::now().timestamp());
                cert_collector.collect(&mut snap, &cfg_snapshot);
                if let Some(d) = snap.tls_cert_days_left {
                    logger.info("cert", &format!("TLS cert days_left={d}"));
                    if d <= 0 {
                        logger.emergency("cert", &format!("TLS cert EXPIRED ({d} days)"));
                    } else if d <= 5 {
                        logger.critical("cert", &format!("TLS cert expires in {d} days"), d as f64, "days", None);
                    } else if d <= 14 {
                        logger.warn_metric("cert", &format!("TLS cert expires in {d} days"), d as f64, "days", None);
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("SIGINT received — shutting down PWDnowMonitoringENV");
                logger.info("monitor", "PWDnowMonitoringENV shutting down (SIGINT)");
                break;
            }
        }
    }
}

/// One complete monitoring cycle: collect → evaluate → act.
/// Returns the snapshot so the caller can feed cross-cycle detectors
/// (SLA P1 leak detector).
async fn poll_cycle(
    sys:    &mut SystemCollector,
    daemon: &DaemonCollector,
    web:    &WebCollector,
    risk:   &mut RiskEngine,
    action: &mut ActionEngine,
    cfg:    &Config,
    log:    &Logger,
) -> Snapshot {
    let ts = Utc::now().timestamp();
    let mut snap = Snapshot::with_ts(ts);

    // Collect metrics (blocking I/O but microseconds — safe to run on tokio thread)
    sys.collect(&mut snap);
    daemon.collect(&mut snap, cfg);
    web.collect(&mut snap, cfg);

    // Evaluate against thresholds + trends
    let events = risk.evaluate(&snap, cfg);

    // Take corrective actions
    if events.is_empty() {
        // Log a brief "all clear" heartbeat every 5 minutes to confirm the monitor is alive
        if ts % 300 < cfg.poll_interval_secs as i64 {
            log.info("monitor", &format!(
                "OK — disk={:.1}% ram={:.0}MiB cpu={:.1}% daemon={} web={}",
                snap.disk_used_pct,
                snap.ram_available_mib,
                snap.cpu_usage_pct,
                if snap.daemon_active && snap.daemon_socket_ok { "UP" } else { "DOWN" },
                if snap.web_pm2_online && snap.web_port_open { "UP" } else { "DOWN" },
            ));
        }
    } else {
        action.process(&events, cfg, log, risk);
    }
    snap
}

/// Parse `--config <path>` from argv.
fn parse_config_arg() -> Option<PathBuf> {
    let args: Vec<String> = std::env::args().collect();
    args.windows(2)
        .find(|w| w[0] == "--config")
        .map(|w| PathBuf::from(&w[1]))
}
