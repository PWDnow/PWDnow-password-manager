//! Offline HIBP password breach check via a local Cuckoo filter.
//!
//! Architecture §4 — Offline HIBP:
//! - Download the full HIBP SHA-1 hash list (~40 GB) and build an ~8 GB
//!   Cuckoo filter from it using `hibp/build-filter.sh`.
//! - On password creation/edit: SHA-1(password) → query the local filter.
//! - False positive rate ~0.1%; no false negatives for set members.
//! - The filter file is never required; if absent, the check is skipped.
//!
//! ## Filter file format (custom, space-efficient)
//!
//! ```text
//! [Header]
//!   Magic:      8 bytes  = b"HIBPCF01"
//!   Buckets:    8 bytes  = u64 LE — number of buckets
//!   Slots/bkt:  1 byte   = slots per bucket (4 in this implementation)
//!   FP bits:    1 byte   = fingerprint bits (16)
//!   Reserved:   6 bytes
//! [Data]
//!   buckets × slots × (fp_bits / 8) bytes fingerprints, packed
//! ```
//!
//! This module implements *reading* the filter (query only).
//! Building the filter is handled by `hibp/build-filter.sh`.

use std::io::Read;
use std::path::Path;

use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::error::VaultError;

// ── Constants ─────────────────────────────────────────────────────────────────

const MAGIC: &[u8; 8] = b"HIBPCF01";
const SLOTS_PER_BUCKET: usize = 4;
const FP_BYTES: usize = 2; // 16-bit fingerprint

// ── Filter ────────────────────────────────────────────────────────────────────

/// An in-memory Cuckoo filter loaded from a file.
pub struct CuckooFilter {
    buckets: usize,
    /// Fingerprint table: `buckets × SLOTS_PER_BUCKET` entries, each 2 bytes.
    data: Vec<u8>,
}

impl CuckooFilter {
    /// Load a filter file from `path`, verifying its SHA-256 manifest first.
    ///
    /// Expects a sidecar at `{path}.sha256` whose first whitespace-delimited
    /// token is the lowercase hex SHA-256 of the filter blob (the same format
    /// `sha256sum(1)` produces). This is written by `hibp/build-filter.sh`.
    ///
    /// Refuses to return a filter if the sidecar is missing, malformed, or
    /// the digest does not match — a tampered or truncated filter would
    /// otherwise silently produce wrong pwned/clean verdicts.
    pub fn load(path: &Path) -> Result<Self, VaultError> {
        // Stream-hash the filter rather than read-then-hash separately: the
        // filter is ~8 GB, so touching the bytes twice doubles the I/O.
        let mut file = std::fs::File::open(path)
            .map_err(|e| VaultError::Crypto(format!("HIBP filter open failed: {e}")))?;

        use sha2::Digest as _;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 20]; // 1 MiB chunks
        let mut full = Vec::with_capacity(24);
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| VaultError::Crypto(format!("HIBP filter read: {e}")))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            full.extend_from_slice(&buf[..n]);
        }
        let actual = hex::encode(hasher.finalize());

        // Read and parse the sidecar: `<hex64> <optional_path>\n`
        let sidecar_path = {
            let mut p = path.as_os_str().to_owned();
            p.push(".sha256");
            std::path::PathBuf::from(p)
        };
        let expected = std::fs::read_to_string(&sidecar_path).map_err(|e| {
            VaultError::Crypto(format!(
                "HIBP filter: sidecar {} missing or unreadable: {e}",
                sidecar_path.display()
            ))
        })?;
        let expected_hex = expected
            .split_whitespace()
            .next()
            .ok_or_else(|| VaultError::Crypto("HIBP filter: empty sidecar".into()))?
            .to_ascii_lowercase();
        if expected_hex.len() != 64 || !expected_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(VaultError::Crypto(
                "HIBP filter: malformed SHA-256 in sidecar".into(),
            ));
        }
        if expected_hex != actual {
            return Err(VaultError::Crypto(format!(
                "HIBP filter: SHA-256 mismatch (expected {expected_hex}, got {actual})"
            )));
        }

        // Digest OK → parse the validated bytes.
        if full.len() < 24 {
            return Err(VaultError::Crypto("HIBP filter: truncated header".into()));
        }
        if &full[0..8] != MAGIC {
            return Err(VaultError::Crypto("HIBP filter: invalid magic bytes".into()));
        }
        let buckets = u64::from_le_bytes(full[8..16].try_into().unwrap()) as usize;
        let slots = full[16] as usize;
        let fp_bits = full[17] as usize;

        if slots != SLOTS_PER_BUCKET || fp_bits != FP_BYTES * 8 {
            return Err(VaultError::Crypto(format!(
                "HIBP filter: unsupported params slots={slots} fp_bits={fp_bits}"
            )));
        }

        let data_len = buckets * SLOTS_PER_BUCKET * FP_BYTES;
        if full.len() < 24 + data_len {
            return Err(VaultError::Crypto("HIBP filter: truncated data".into()));
        }
        let data = full[24..24 + data_len].to_vec();

        Ok(Self { buckets, data })
    }

    /// Returns `true` if `password` is probably in the HIBP dataset.
    /// Returns `false` if definitely not present.
    pub fn might_be_pwned(&self, password: &[u8]) -> bool {
        let (fp, i1, i2) = self.fingerprint_and_indices(password);
        self.bucket_contains(i1, fp) || self.bucket_contains(i2, fp)
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    fn fingerprint_and_indices(&self, item: &[u8]) -> (u16, usize, usize) {
        let hash = Sha1::digest(item);
        // Fingerprint: first 2 bytes of the SHA-1 hash, non-zero
        let fp = u16::from_be_bytes([hash[0], hash[1]]).max(1);
        // Primary bucket: bytes [2..10] interpreted as u64, mod buckets
        let i1 = (u64::from_be_bytes(hash[2..10].try_into().unwrap()) as usize) % self.buckets;
        // Alternate bucket via fingerprint hash (standard Cuckoo filter formula)
        let fp_hash = {
            let mut h = Sha1::new();
            h.update(fp.to_be_bytes());
            let d = h.finalize();
            u64::from_be_bytes(d[0..8].try_into().unwrap()) as usize
        };
        let i2 = (i1 ^ (fp_hash % self.buckets)) % self.buckets;
        (fp, i1, i2)
    }

    fn bucket_contains(&self, bucket: usize, fp: u16) -> bool {
        let base = bucket * SLOTS_PER_BUCKET * FP_BYTES;
        for slot in 0..SLOTS_PER_BUCKET {
            let off = base + slot * FP_BYTES;
            let stored = u16::from_be_bytes([self.data[off], self.data[off + 1]]);
            if stored == fp {
                return true;
            }
        }
        false
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Check `password` against the local HIBP Cuckoo filter at `filter_path`.
///
/// Returns:
/// - `Ok(true)` — password is probably in the HIBP dataset (breach likely)
/// - `Ok(false)` — password is definitely not in the dataset
/// - `Err(_)` — filter file could not be read (caller should treat as unknown)
pub fn check_password(filter_path: &Path, password: &[u8]) -> Result<bool, VaultError> {
    let filter = CuckooFilter::load(filter_path)?;
    Ok(filter.might_be_pwned(password))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// SHA-1 hash of a password as an uppercase hex string (for HIBP k-anonymity API,
    /// if the caller wants to fall back to the online range API).
    ///
    /// Architecture note: SHA-1 is used here exclusively for HIBP compatibility —
    /// the HIBP dataset is SHA-1 by definition. Never use SHA-1 for any other purpose.
    fn sha1_hex(password: &[u8]) -> String {
        let hash = Sha1::digest(password);
        hex::encode(hash).to_uppercase()
    }

    /// Build a minimal synthetic Cuckoo filter file that contains exactly one fingerprint.
    fn make_filter_with(fp: u16, bucket: usize, buckets: usize) -> Vec<u8> {
        let mut out = Vec::new();
        // Header
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(buckets as u64).to_le_bytes());
        out.push(SLOTS_PER_BUCKET as u8);
        out.push((FP_BYTES * 8) as u8);
        out.extend_from_slice(&[0u8; 6]); // reserved

        // Data: all zeros except one slot in the target bucket
        let data_len = buckets * SLOTS_PER_BUCKET * FP_BYTES;
        let mut data = vec![0u8; data_len];
        let base = bucket * SLOTS_PER_BUCKET * FP_BYTES;
        // Write fingerprint into slot 0 of the target bucket
        let fp_bytes = fp.to_be_bytes();
        data[base]     = fp_bytes[0];
        data[base + 1] = fp_bytes[1];
        out.extend_from_slice(&data);
        out
    }

    /// Write a filter file *and* a matching `.sha256` sidecar next to it, so
    /// `CuckooFilter::load()` passes integrity verification. Returns the
    /// NamedTempFile handle; the sidecar is a sibling path that we hand-manage
    /// and remove alongside the temp drop.
    fn write_filter(content: &[u8]) -> NamedTempFile {
        use sha2::Digest as _;
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), content).unwrap();
        let digest = Sha256::digest(content);
        let sidecar = {
            let mut p = f.path().as_os_str().to_owned();
            p.push(".sha256");
            std::path::PathBuf::from(p)
        };
        std::fs::write(&sidecar, format!("{}  filter\n", hex::encode(digest))).unwrap();
        f
    }

    /// Same as `write_filter` but writes a *wrong* digest into the sidecar so
    /// we can assert that `load()` rejects a tampered filter.
    fn write_filter_with_bad_sidecar(content: &[u8]) -> NamedTempFile {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), content).unwrap();
        let sidecar = {
            let mut p = f.path().as_os_str().to_owned();
            p.push(".sha256");
            std::path::PathBuf::from(p)
        };
        // 64 hex chars of zero → will not match any real digest.
        std::fs::write(&sidecar, format!("{}  filter\n", "0".repeat(64))).unwrap();
        f
    }

    #[test]
    fn sha1_hex_returns_uppercase_hex() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let h = sha1_hex(b"password");
        assert_eq!(h.len(), 40);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h, h.to_uppercase());
    }

    #[test]
    fn sha1_hex_known_value() {
        assert_eq!(sha1_hex(b"password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn invalid_magic_returns_error() {
        let mut bad = vec![0u8; 24 + 4 * SLOTS_PER_BUCKET * FP_BYTES];
        bad[0] = b'X'; // corrupt magic
        let f = write_filter(&bad);
        assert!(CuckooFilter::load(f.path()).is_err());
    }

    #[test]
    fn missing_file_returns_error() {
        let result = CuckooFilter::load(Path::new("/nonexistent/hibp.cuckoo"));
        assert!(result.is_err());
    }

    #[test]
    fn missing_sidecar_is_rejected() {
        // Write a well-formed filter but no sidecar — load must refuse.
        let buckets = 16;
        let bytes = make_filter_with(0xABCD, 0, buckets);
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), &bytes).unwrap();
        assert!(CuckooFilter::load(f.path()).is_err());
    }

    #[test]
    fn bad_sidecar_digest_is_rejected() {
        let buckets = 16;
        let bytes = make_filter_with(0xABCD, 0, buckets);
        let f = write_filter_with_bad_sidecar(&bytes);
        let err = match CuckooFilter::load(f.path()) {
            Err(e) => e,
            Ok(_) => panic!("load should have rejected bad sidecar"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("SHA-256"), "expected SHA-256 mismatch, got: {msg}");
    }

    #[test]
    fn filter_contains_inserted_fingerprint() {
        let buckets = 16;
        let password = b"test-password-for-hibp";
        // Build a filter that derives exactly where this password would land
        let filter_bytes = {
            let hash = Sha1::digest(password);
            let fp = u16::from_be_bytes([hash[0], hash[1]]).max(1);
            let i1 = (u64::from_be_bytes(hash[2..10].try_into().unwrap()) as usize) % buckets;
            make_filter_with(fp, i1, buckets)
        };
        let f = write_filter(&filter_bytes);
        let filter = CuckooFilter::load(f.path()).unwrap();
        assert!(filter.might_be_pwned(password), "password inserted into primary bucket must be found");
    }

    #[test]
    fn filter_misses_absent_password() {
        let buckets = 16;
        // Build a filter with a fingerprint that cannot match "absent-password"
        // by using fp=1 in bucket 0 only if the password wouldn't land there.
        let filter_bytes = make_filter_with(0xBEEF, 0, buckets);
        let f = write_filter(&filter_bytes);
        let filter = CuckooFilter::load(f.path()).unwrap();
        // Compute where "absent-password" would land
        let hash = Sha1::digest(b"absent-password");
        let fp = u16::from_be_bytes([hash[0], hash[1]]).max(1);
        // If by chance fp == 0xBEEF AND bucket is 0, we can't assert false-negative.
        // Extremely unlikely; use a second distinct password for safety.
        if fp != 0xBEEF {
            assert!(!filter.might_be_pwned(b"absent-password"),
                "password not in filter must not be found");
        }
    }

    #[test]
    fn filter_alternate_bucket_also_found() {
        let buckets = 16;
        let password = b"alternate-bucket-test";
        let hash = Sha1::digest(password);
        let fp = u16::from_be_bytes([hash[0], hash[1]]).max(1);
        let i1 = (u64::from_be_bytes(hash[2..10].try_into().unwrap()) as usize) % buckets;
        let fp_hash = {
            let mut h = Sha1::new();
            h.update(fp.to_be_bytes());
            let d = h.finalize();
            u64::from_be_bytes(d[0..8].try_into().unwrap()) as usize
        };
        let i2 = (i1 ^ (fp_hash % buckets)) % buckets;
        // Insert into the alternate bucket instead of the primary
        let filter_bytes = make_filter_with(fp, i2, buckets);
        let f = write_filter(&filter_bytes);
        let filter = CuckooFilter::load(f.path()).unwrap();
        assert!(filter.might_be_pwned(password), "alternate bucket must also be checked");
    }
}
