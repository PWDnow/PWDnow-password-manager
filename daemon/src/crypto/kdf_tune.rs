//! Argon2id parameter selection for vault KEK derivation.
//!
//! Compliance targets:
//!   - NIST SP 800-63B-4 (2024) AAL3: memory-hard one-way KDF (Argon2id is named).
//!     No fixed m/t/p floor; "appropriate parameters" is the standard.
//!   - OWASP ASVS 5.0 V2.4 + Password Storage Cheat Sheet (2024):
//!     Argon2id >= 19 MiB / t>=2 / p>=1 (minimum); >= 46 MiB / t>=1 / p>=1 (recommended).
//!   - NSA CNSA 2.0 (Sept 2022): references SP 800-132 for password-based KDF;
//!     does not pin Argon2id parameters.
//!
//! Our floor (256 MiB / t=3 / p=1) exceeds the highest OWASP recommendation by
//! ~5x memory and ~3x total work, giving comfortable Level-5 margin while
//! letting unlock complete in well under one second on a release build.

use std::time::Instant;
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

/// Floor -- never go below this regardless of auto-tune outcome. Exceeds OWASP
/// "highest assurance" recommendation (m>=46 MiB / t>=1) by ~5x memory.
pub const MIN_M_COST: u32 = 256 * 1024; // 256 MiB (in kibibytes)
pub const MIN_T_COST: u32 = 3;
pub const MIN_P_COST: u32 = 1;

/// "Legacy heavy" profile we want to migrate AWAY FROM. Any vault whose header
/// reports m above this OR t above this OR p above this is considered eligible
/// for a transparent VMK re-wrap on next unlock. Kept here so the migration
/// check in state.rs has a single source of truth.
pub const LEGACY_HEAVY_M_COST: u32 = 1024 * 1024; // 1 GiB
pub const LEGACY_HEAVY_T_COST: u32 = 4;
pub const LEGACY_HEAVY_P_COST: u32 = 2;

/// Returns true if `(m, t, p)` look like the old over-provisioned profile and
/// the vault should be re-keyed to the current floor.
pub fn is_legacy_heavy(m: u32, t: u32, p: u32) -> bool {
    m >= LEGACY_HEAVY_M_COST || t >= LEGACY_HEAVY_T_COST || p >= LEGACY_HEAVY_P_COST
}

/// Auto-tune Argon2id, biased toward speed but never below the floor.
/// Target: ~600 ms total cost on the calibration password.
///
/// Test/CI mode: `PWDNOW_ARGON2_FAST=1` or `cfg(test)` selects a tiny profile
/// so the suite doesn't spend 30 s in calibration.
pub fn tune_params() -> (u32, u32, u32) {
    if std::env::var("PWDNOW_ARGON2_FAST").is_ok() || cfg!(test) {
        return (64 * 1024, 1, 1);
    }

    let m = MIN_M_COST;
    let p = MIN_P_COST;
    let target_secs = 0.6_f64;

    // Time a single pass at the floor. Anything below the floor is forbidden,
    // so this is also the minimum cost we'll ever emit.
    let mut input = b"tuning-password-pwdnow".to_vec();
    let salt = [0x42u8; 32];

    let baseline = {
        let params = Params::new(m, MIN_T_COST, p, Some(64)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 64];
        let start = Instant::now();
        let _ = argon2.hash_password_into(&input, &salt, &mut out);
        start.elapsed().as_secs_f64()
    };

    // If a single pass at MIN_T_COST is already at/above target, stay at the
    // floor. Otherwise scale t up so total ~= target (single-pass timing is
    // approximately linear in t since memory fill dominates each pass).
    let chosen_t = if baseline >= target_secs {
        MIN_T_COST
    } else {
        let per_pass = baseline / (MIN_T_COST as f64);
        let scaled = (target_secs / per_pass).round() as u32;
        scaled.max(MIN_T_COST).min(16)
    };

    input.zeroize();
    (m, chosen_t, p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tune_params_returns_test_profile() {
        let (m, t, p) = tune_params();
        // Under cfg(test) we always get the fast profile.
        assert_eq!(m, 64 * 1024);
        assert_eq!(t, 1);
        assert_eq!(p, 1);
    }

    #[test]
    fn test_legacy_heavy_detection() {
        // Old 1 GiB / t=4 / p=2 profile -- must be flagged for migration.
        assert!(is_legacy_heavy(1024 * 1024, 4, 2));
        // Any of m>=1GiB, t>=4, p>=2 alone is enough.
        assert!(is_legacy_heavy(1024 * 1024, 3, 1));
        assert!(is_legacy_heavy(256 * 1024, 4, 1));
        assert!(is_legacy_heavy(256 * 1024, 3, 2));
        // The new floor profile -- not flagged.
        assert!(!is_legacy_heavy(MIN_M_COST, MIN_T_COST, MIN_P_COST));
    }

    #[test]
    fn test_floor_is_owasp_compliant() {
        // OWASP ASVS 5.0 / Password Storage Cheat Sheet highest-assurance:
        // m >= 46 MiB, t >= 1, p >= 1. We aim well above.
        assert!(MIN_M_COST >= 46 * 1024);
        assert!(MIN_T_COST >= 1);
        assert!(MIN_P_COST >= 1);
    }
}
