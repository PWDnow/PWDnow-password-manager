//! System metrics collector — reads directly from /proc and libc syscalls.
//! No external processes are spawned here; zero subprocess overhead.

use std::io;
use std::time::{Duration, Instant};

use super::Snapshot;

// ── CPU state (kept between polls to compute delta) ───────────────────────────

#[derive(Default, Clone, Copy)]
pub struct CpuState {
    idle:  u64,
    total: u64,
    // disk I/O wait ticks
    iowait: u64,
    // monotonic timestamp for disk I/O
    disk_read_ms:  u64,
    disk_write_ms: u64,
}

/// Stateful collector — carry over between ticks to compute deltas.
pub struct SystemCollector {
    prev_cpu:  CpuState,
    prev_disk: DiskState,
    prev_ts:   Instant,
}

#[derive(Default, Clone, Copy)]
struct DiskState {
    io_ms_total: u64,
    wall_ms:     u64,
}

impl SystemCollector {
    pub fn new() -> Self {
        let prev_disk = read_disk_state().unwrap_or_default();
        Self {
            prev_cpu:  read_cpu_state().unwrap_or_default(),
            prev_disk,
            prev_ts:   Instant::now(),
        }
    }

    /// Populate the system portion of a `Snapshot`.
    pub fn collect(&mut self, snap: &mut Snapshot) {
        // ── RAM ──────────────────────────────────────────────────────────────────
        if let Ok(mem) = read_meminfo() {
            snap.ram_total_mib    = mem.total as f64 / 1024.0;
            snap.ram_available_mib = mem.available as f64 / 1024.0;
            snap.swap_free_mib    = mem.swap_free as f64 / 1024.0;
        }

        // ── CPU & load ───────────────────────────────────────────────────────────
        let now_cpu = read_cpu_state().unwrap_or(self.prev_cpu);
        let delta_total = now_cpu.total.saturating_sub(self.prev_cpu.total);
        let delta_idle  = now_cpu.idle.saturating_sub(self.prev_cpu.idle);
        let delta_iowait = now_cpu.iowait.saturating_sub(self.prev_cpu.iowait);

        if delta_total > 0 {
            snap.cpu_usage_pct = 100.0 * (delta_total - delta_idle) as f64 / delta_total as f64;
            snap.disk_io_pct   = 100.0 * delta_iowait as f64 / delta_total as f64;
        }
        self.prev_cpu = now_cpu;

        // Load average from /proc/loadavg
        if let Ok(load) = read_loadavg() {
            snap.load_avg_1 = load;
        }

        // ── Disk space (statvfs on /) ─────────────────────────────────────────
        if let Ok((used_pct, free_gib)) = read_disk_space("/") {
            snap.disk_used_pct = used_pct;
            snap.disk_free_gib = free_gib;
        }
    }
}

// ── /proc parsers ─────────────────────────────────────────────────────────────

struct MemInfo {
    total:     u64, // kB
    available: u64, // kB
    swap_free: u64, // kB
}

fn read_meminfo() -> io::Result<MemInfo> {
    let raw = std::fs::read_to_string("/proc/meminfo")?;
    let mut total     = 0u64;
    let mut available = 0u64;
    let mut swap_free = 0u64;

    for line in raw.lines() {
        // Format: "MemTotal:       3456789 kB"
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap_or("");
        let val: u64 = parts.next().unwrap_or("0").parse().unwrap_or(0);
        match key {
            "MemTotal:"     => total     = val,
            "MemAvailable:" => available = val,
            "SwapFree:"     => swap_free = val,
            _ => {}
        }
    }
    Ok(MemInfo { total, available, swap_free })
}

fn read_cpu_state() -> io::Result<CpuState> {
    let raw = std::fs::read_to_string("/proc/stat")?;
    // First line: "cpu  user nice system idle iowait irq softirq steal guest guest_nice"
    let line = raw.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    parts.next(); // skip "cpu"

    let values: Vec<u64> = parts
        .take(10)
        .map(|s| s.parse().unwrap_or(0))
        .collect();

    let user    = values.first().copied().unwrap_or(0);
    let nice    = values.get(1).copied().unwrap_or(0);
    let system  = values.get(2).copied().unwrap_or(0);
    let idle    = values.get(3).copied().unwrap_or(0);
    let iowait  = values.get(4).copied().unwrap_or(0);
    let irq     = values.get(5).copied().unwrap_or(0);
    let softirq = values.get(6).copied().unwrap_or(0);
    let steal   = values.get(7).copied().unwrap_or(0);

    let total = user + nice + system + idle + iowait + irq + softirq + steal;
    Ok(CpuState { idle, total, iowait, ..Default::default() })
}

fn read_loadavg() -> io::Result<f64> {
    let raw = std::fs::read_to_string("/proc/loadavg")?;
    let val: f64 = raw
        .split_whitespace()
        .next()
        .unwrap_or("0.0")
        .parse()
        .unwrap_or(0.0);
    Ok(val)
}

fn read_disk_space(path: &str) -> io::Result<(f64, f64)> {
    use std::ffi::CString;

    let cpath = CString::new(path).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, e)
    })?;

    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(cpath.as_ptr(), &mut stat) != 0 {
            return Err(io::Error::last_os_error());
        }
        let total_bytes = stat.f_blocks as u64 * stat.f_frsize as u64;
        let free_bytes  = stat.f_bavail as u64 * stat.f_frsize as u64;
        let used_bytes  = total_bytes.saturating_sub(free_bytes);

        let used_pct = if total_bytes > 0 {
            100.0 * used_bytes as f64 / total_bytes as f64
        } else {
            0.0
        };
        let free_gib = free_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        Ok((used_pct, free_gib))
    }
}

fn read_disk_state() -> io::Result<DiskState> {
    // /proc/diskstats: major minor name reads ... read_ms writes ... write_ms ...
    // We sum io_ms across all non-loop/non-ram devices.
    let raw = std::fs::read_to_string("/proc/diskstats")?;
    let mut io_ms_total = 0u64;
    for line in raw.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 13 {
            continue;
        }
        let name = parts[2];
        // Skip loop devices, ram disks, and partitions (only take whole disks)
        if name.starts_with("loop") || name.starts_with("ram") || name.ends_with(|c: char| c.is_ascii_digit()) {
            // Keep only if it's a base device like sda, nvme0n1, mmcblk0
            if !name.starts_with("nvme") && !name.starts_with("mmcblk") {
                continue;
            }
        }
        // field 13 (0-indexed) = time doing I/O in ms
        let io_ms: u64 = parts.get(12).unwrap_or(&"0").parse().unwrap_or(0);
        io_ms_total += io_ms;
    }
    let wall_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64;
    Ok(DiskState { io_ms_total, wall_ms })
}

// ── libc link ─────────────────────────────────────────────────────────────────
// We need libc for statvfs — add as a dependency.
extern crate libc;
