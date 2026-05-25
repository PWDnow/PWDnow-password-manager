//! Web / PM2 health collector.
//!
//! Three independent checks:
//!   1. `pm2 jlist` JSON parse — PM2's view of the process
//!   2. TCP connect to the web port — network-layer liveness
//!   3. Raw HTTP GET /health — application-layer liveness

use std::io::{self, Read, Write};
use std::net::{TcpStream, SocketAddr};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tracing::debug;

use super::Snapshot;
use crate::config::Config;

pub struct WebCollector;

impl WebCollector {
    pub fn new() -> Self { Self }

    pub fn collect(&self, snap: &mut Snapshot, cfg: &Config) {
        // ── 1. PM2 jlist ─────────────────────────────────────────────────────
        if let Some(pm2) = query_pm2("pwdnow") {
            snap.web_pm2_online   = pm2.online;
            snap.web_pm2_restarts = pm2.restarts;
        }

        // ── 2. TCP port check ─────────────────────────────────────────────────
        let addr: SocketAddr = format!("127.0.0.1:{}", cfg.paths.web_port)
            .parse()
            .expect("static port string is valid");

        let tcp_timeout = Duration::from_millis(cfg.thresholds.http_timeout_ms);
        snap.web_port_open = TcpStream::connect_timeout(&addr, tcp_timeout).is_ok();

        // ── 3. HTTP /health ───────────────────────────────────────────────────
        if snap.web_port_open {
            let t0 = Instant::now();
            match http_get_health(&addr, &cfg.paths.health_endpoint, tcp_timeout) {
                Ok(200) => {
                    snap.web_health_ok = true;
                    snap.web_health_ms = t0.elapsed().as_secs_f64() * 1000.0;
                }
                Ok(code) => {
                    debug!("web /health returned HTTP {code}");
                    snap.web_health_ok = false;
                    snap.web_health_ms = t0.elapsed().as_secs_f64() * 1000.0;
                }
                Err(e) => {
                    debug!("web /health error: {e}");
                    snap.web_health_ok = false;
                    snap.web_health_ms = t0.elapsed().as_secs_f64() * 1000.0;
                }
            }
        }

        // ── nginx ─────────────────────────────────────────────────────────────
        snap.nginx_active = crate::collector::daemon::check_systemctl_active("nginx");

        // Check port 443 (nginx HTTPS)
        let nginx_addr: SocketAddr = "127.0.0.1:443".parse().expect("static");
        snap.nginx_port_ok = TcpStream::connect_timeout(&nginx_addr, tcp_timeout).is_ok();
        // If 443 not available, try 80
        if !snap.nginx_port_ok {
            let http_addr: SocketAddr = "127.0.0.1:80".parse().expect("static");
            snap.nginx_port_ok = TcpStream::connect_timeout(&http_addr, tcp_timeout).is_ok();
        }
    }
}

// ── PM2 JSON parser ───────────────────────────────────────────────────────────

struct Pm2Status {
    online:   bool,
    restarts: u32,
}

/// Partial PM2 process descriptor — we only parse what we need.
#[derive(Deserialize)]
struct Pm2Process {
    name: String,
    pm2_env: Pm2Env,
}

#[derive(Deserialize)]
struct Pm2Env {
    status:          String,
    restart_time:    Option<u32>,
}

fn query_pm2(app_name: &str) -> Option<Pm2Status> {
    let output = std::process::Command::new("pm2")
        .args(["jlist"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let list: Vec<Pm2Process> =
        serde_json::from_slice(&output.stdout).ok()?;

    list.into_iter()
        .find(|p| p.name == app_name)
        .map(|p| Pm2Status {
            online:   p.pm2_env.status == "online",
            restarts: p.pm2_env.restart_time.unwrap_or(0),
        })
}

// ── Minimal raw HTTP/1.1 GET (no heavy dependency) ────────────────────────────

/// Returns the HTTP status code or an error.
fn http_get_health(
    addr:     &SocketAddr,
    path:     &str,
    timeout:  Duration,
) -> io::Result<u16> {
    let mut stream = TcpStream::connect_timeout(addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let host = addr.ip().to_string();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: pwdnow-monitor/0.1\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;

    // Read just enough to parse the status line
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf)?;
    let response = std::str::from_utf8(&buf[..n])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // "HTTP/1.1 200 OK\r\n..."
    let status: u16 = response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    Ok(status)
}
