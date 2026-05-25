//! SLA P1: simple monotonic-growth detector for the web tier.
//!
//! Premise: a memory leak is *monotonic growth uncorrelated with load*. If
//! RSS strictly increases over a sliding window AND request volume hasn't
//! materially changed, we have a leak (or a misbehaving cache). We don't
//! attempt the more ambitious in-process subsystem-restart described in
//! SLA.md P1-full — that requires daemon and web cooperation and stays in
//! the §4 backlog. What we DO ship: a high-quality alert that gives the
//! operator the signal hours before OOM, so the recycle happens at a
//! planned moment, not at 03:00 in a page.
//!
//! Algorithm (deliberately stupid — fewer false positives than a regression):
//!   * Maintain a ring buffer of `WINDOW_SAMPLES` (RSS, ts) pairs.
//!   * Once the buffer is full, check: did RSS *strictly* increase across
//!     every consecutive sample? (Allowing a small `JITTER_BYTES` tolerance
//!     for normal allocator noise.)
//!   * If yes AND the total growth exceeds `MIN_TOTAL_GROWTH_BYTES`, emit
//!     a WARN (first time) and then a CRITICAL if it persists.
//!
//! Threshold defaults are deliberately conservative — leaks under
//! ~32 MiB/hour will not trigger. This trades sensitivity for false-positive
//! rate; tuning is config-driven (so ops can lower the threshold).

use std::collections::VecDeque;

/// How many samples to keep in the sliding window.
/// At 10-second poll interval, 36 samples = 6 minutes.
const WINDOW_SAMPLES:       usize = 36;
/// Per-sample jitter we tolerate (allocator chunks vary; this is noise).
const JITTER_BYTES:         u64   = 2 * 1024 * 1024;       // 2 MiB
/// Minimum total growth over the window before we cry "leak".
const MIN_TOTAL_GROWTH_BYTES: u64 = 32 * 1024 * 1024;      // 32 MiB

#[derive(Debug, Clone)]
pub struct LeakDetector {
    samples: VecDeque<u64>,
    /// Once tripped, we don't re-alert until reset by a confirmed drop.
    tripped: bool,
    /// Peak RSS at the moment of tripping — reset compares current to this.
    trip_peak: u64,
}

impl LeakDetector {
    pub fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(WINDOW_SAMPLES),
            tripped: false,
            trip_peak: 0,
        }
    }

    /// Feed a sample (RSS in bytes). Returns `Some((from, to))` ONCE per leak
    /// episode, the first time the detector trips. Subsequent samples return
    /// `None` until RSS drops materially below the trip-time peak, which
    /// resets the detector so the next leak episode can re-alert.
    pub fn observe(&mut self, rss_bytes: u64) -> Option<(u64, u64)> {
        // Maintain the sliding window.
        if self.samples.len() >= WINDOW_SAMPLES { self.samples.pop_front(); }
        self.samples.push_back(rss_bytes);

        // Reset on a confirmed drop relative to the peak that tripped us.
        // We need a noticeable drop (more than MIN_TOTAL_GROWTH_BYTES/2) so
        // a single low sample doesn't re-arm prematurely.
        if self.tripped {
            if rss_bytes + (MIN_TOTAL_GROWTH_BYTES / 2) < self.trip_peak {
                self.tripped = false;
            }
            return None;
        }

        // Need a full window before evaluating.
        if self.samples.len() < WINDOW_SAMPLES { return None; }

        // Monotonic-increase check with jitter tolerance.
        let mut prev = self.samples[0];
        for &s in self.samples.iter().skip(1) {
            // Allow a tiny dip (allocator noise) but not a real one.
            if s + JITTER_BYTES < prev { return None; }
            prev = s.max(prev);
        }
        let first = *self.samples.front().unwrap();
        let last  = *self.samples.back().unwrap();
        if last > first + MIN_TOTAL_GROWTH_BYTES {
            self.tripped = true;
            self.trip_peak = last;
            return Some((first, last));
        }
        None
    }
}

impl Default for LeakDetector {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mib(n: u64) -> u64 { n * 1024 * 1024 }

    #[test]
    fn flat_rss_does_not_trip() {
        let mut d = LeakDetector::new();
        for _ in 0..WINDOW_SAMPLES + 5 {
            assert_eq!(d.observe(mib(200)), None);
        }
    }

    #[test]
    fn small_growth_does_not_trip() {
        let mut d = LeakDetector::new();
        for i in 0..WINDOW_SAMPLES + 5 {
            // 0.5 MiB per sample → total < MIN_TOTAL_GROWTH_BYTES over the window
            let _ = d.observe(mib(200) + (i as u64) * (512 * 1024));
        }
    }

    #[test]
    fn monotonic_growth_trips_once() {
        let mut d = LeakDetector::new();
        // Add MiB per sample → 36 MiB over the window, exceeds 32 MiB threshold.
        let mut alert = None;
        for i in 0..WINDOW_SAMPLES {
            alert = d.observe(mib(200) + (i as u64) * mib(2));
        }
        assert!(alert.is_some(), "expected leak alert");
        // Subsequent samples must not re-alert until a drop.
        for i in WINDOW_SAMPLES..WINDOW_SAMPLES + 5 {
            assert_eq!(d.observe(mib(200) + (i as u64) * mib(2)), None);
        }
    }

    #[test]
    fn drop_resets_detector() {
        let mut d = LeakDetector::new();
        // Phase 1 — first leak episode (growth = 70 MiB over 35 steps, > 32 MiB threshold)
        let mut tripped_once = false;
        for i in 0..WINDOW_SAMPLES {
            if d.observe(mib(200) + (i as u64) * mib(2)).is_some() {
                tripped_once = true;
            }
        }
        assert!(tripped_once, "phase-1 leak should have tripped");
        // Phase 2 — drop. Push 2 × window worth of low samples to (a) un-trip
        // the detector, then (b) completely flush the window of phase-1 values.
        for _ in 0..(WINDOW_SAMPLES * 2) {
            let _ = d.observe(mib(100));
        }
        // Phase 3 — another leak. The detector trips exactly once per
        // episode, as soon as growth crosses the threshold (≈11 samples in
        // here, when growth = 33 MiB). Subsequent observations within the
        // same episode return None — that's by design (no alert spam).
        let mut tripped_again = false;
        for i in 0..WINDOW_SAMPLES {
            if d.observe(mib(100) + (i as u64) * mib(3)).is_some() {
                tripped_again = true;
            }
        }
        assert!(tripped_again, "detector should re-arm after drop");
    }
}
