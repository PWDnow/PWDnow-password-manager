//! Encrypted vault sync via Cloudflare R2 (S3-compatible) or any S3-compatible store.
//!
//! # Status: NOT WIRED INTO IPC
//! This module is complete but has no IPC handler — `Request::SyncNow` does not exist.
//! To activate: add `Request::SyncNow` and `Response::SyncResult` to protocol.rs,
//! add a dispatch arm in socket.rs, and schedule a `tokio::time::interval` driver in
//! state.rs.  Until then this module is intentionally unreachable from the daemon.
#![allow(dead_code)]
//!
//! Architecture §8 — Sync Architecture:
//!
//! **What is synced**: the entire SQLCipher-encrypted vault file. The sync layer
//! never decrypts anything — it transfers opaque bytes that are already protected
//! by AES-256-GCM (SQLCipher page encryption).
//!
//! **Protocol**:
//! 1. Daemon computes BLAKE3 hash of the current vault file.
//! 2. Compares to the remote ETag / stored hash.
//! 3. If local is newer: compress with zstd, upload.
//! 4. If remote is newer: download, verify BLAKE3, replace local file.
//! 5. Conflict: both sides changed since last sync → download remote as `.conflict`,
//!    report to UI for manual merge.
//!
//! **Authentication**: Cloudflare API token with R2 Object Write permission.
//! The token is stored encrypted in `vault_meta` under key `sync_token_enc`
//! and decrypted by the daemon with the VMK — never stored in plaintext.
//!
//! **Cloudflare Zero Trust**: The daemon itself is not responsible for ZT tunnel
//! setup. The Cloudflare WARP client / `cloudflared` handles that. The daemon
//! simply makes HTTPS calls to the configured endpoint.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::VaultError;

// ── Config ────────────────────────────────────────────────────────────────────

/// Sync configuration loaded from `vault_meta`.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// S3-compatible endpoint URL (e.g. `https://<account>.r2.cloudflarestorage.com`).
    pub endpoint: String,
    /// Bucket name.
    pub bucket: String,
    /// Object key (typically the vault UUID).
    pub object_key: String,
    /// Cloudflare API token (plaintext; caller must decrypt from vault_meta).
    pub api_token: String,
}

// ── Result types ──────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub enum SyncOutcome {
    /// Local vault was uploaded (local was newer or remote was absent).
    Uploaded,
    /// Remote vault was downloaded (remote was newer).
    Downloaded,
    /// Both sides changed — conflict file written alongside vault.
    Conflict { conflict_path: PathBuf },
    /// No action needed (local and remote are identical).
    UpToDate,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compute BLAKE3 hash of a file. Used to detect local/remote changes and verify
/// integrity of downloaded files before replacing the live vault.
pub fn file_blake3(path: &Path) -> Result<[u8; 32], VaultError> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| VaultError::Io(e))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(VaultError::Io)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Compress `data` with zstd at level 3 (fast compression, ~2–3× ratio for SQLite).
fn compress(data: &[u8]) -> Result<Vec<u8>, VaultError> {
    zstd::encode_all(data, 3)
        .map_err(|e| VaultError::Crypto(format!("zstd compress: {e}")))
}

/// Decompress zstd-compressed bytes.
fn decompress(data: &[u8]) -> Result<Vec<u8>, VaultError> {
    zstd::decode_all(data)
        .map_err(|e| VaultError::Crypto(format!("zstd decompress: {e}")))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── SyncClient ────────────────────────────────────────────────────────────────

/// S3-compatible sync client for vault file transfer.
///
/// All network I/O uses `ureq` (pure-Rust HTTP client).
/// TLS is handled by `rustls` — no OpenSSL dependency required.
pub struct SyncClient {
    config: SyncConfig,
}

impl SyncClient {
    pub fn new(config: SyncConfig) -> Self {
        Self { config }
    }

    /// Synchronise `vault_path` with the remote object store.
    ///
    /// Returns the outcome so the daemon can log and notify the UI.
    pub fn sync(&self, vault_path: &Path) -> Result<SyncOutcome, VaultError> {
        let local_hash = file_blake3(vault_path)?;
        let remote_info = self.head_object()?;

        match remote_info {
            None => {
                // Remote object does not exist — upload immediately
                self.upload(vault_path, &local_hash)?;
                Ok(SyncOutcome::Uploaded)
            }
            Some(remote) => {
                if remote.blake3 == local_hash {
                    return Ok(SyncOutcome::UpToDate);
                }
                if remote.uploaded_at > remote.local_modified_at {
                    // Remote is newer — download and verify
                    let conflict = self.download(vault_path, &remote.blake3)?;
                    if conflict {
                        let mut cp = vault_path.to_path_buf();
                        let stem = cp.file_stem().map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| "vault".into());
                        cp.set_file_name(format!("{stem}.conflict.{}", now_secs()));
                        Ok(SyncOutcome::Conflict { conflict_path: cp })
                    } else {
                        Ok(SyncOutcome::Downloaded)
                    }
                } else {
                    // Local is newer — upload
                    self.upload(vault_path, &local_hash)?;
                    Ok(SyncOutcome::Uploaded)
                }
            }
        }
    }

    // ── Private ───────────────────────────────────────────────────────────────

    /// Build the object URL.
    fn object_url(&self) -> String {
        format!("{}/{}/{}", self.config.endpoint.trim_end_matches('/'),
                self.config.bucket, self.config.object_key)
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.config.api_token)
    }

    fn head_object(&self) -> Result<Option<RemoteInfo>, VaultError> {
        let agent = ureq::agent();
        let resp = agent
            .head(&self.object_url())
            .set("Authorization", &self.auth_header())
            .call();
        match resp {
            Ok(r) => {
                let blake3_hex = r.header("x-amz-meta-blake3").unwrap_or_default();
                let blake3 = parse_blake3_hex(blake3_hex)?;
                let uploaded_at = r.header("x-amz-meta-uploaded-at")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let local_modified_at = r.header("x-amz-meta-local-modified-at")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                Ok(Some(RemoteInfo { blake3, uploaded_at, local_modified_at }))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(VaultError::Sync(format!("HEAD object: {e}"))),
        }
    }

    fn upload(&self, vault_path: &Path, hash: &[u8; 32]) -> Result<(), VaultError> {
        let data = std::fs::read(vault_path).map_err(VaultError::Io)?;
        let compressed = compress(&data)?;
        let mtime = std::fs::metadata(vault_path)
            .and_then(|m| m.modified())
            .map(|t| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs())
            .unwrap_or(0);

        let agent = ureq::agent();
        agent
            .put(&self.object_url())
            .set("Authorization", &self.auth_header())
            .set("Content-Type", "application/octet-stream")
            .set("x-amz-meta-blake3", &hex::encode(hash))
            .set("x-amz-meta-uploaded-at", &now_secs().to_string())
            .set("x-amz-meta-local-modified-at", &mtime.to_string())
            .send_bytes(&compressed)
            .map_err(|e| VaultError::Sync(format!("PUT object: {e}")))?;
        Ok(())
    }

    /// Download the remote object, verify its BLAKE3 hash, and atomically
    /// replace the local vault file.  Returns `true` if a conflict was detected.
    fn download(&self, vault_path: &Path, expected_hash: &[u8; 32]) -> Result<bool, VaultError> {
        let local_hash = file_blake3(vault_path)?;
        // If local has changed since last sync record, it's a conflict
        let conflict = local_hash != *expected_hash;

        let agent = ureq::agent();
        let resp = agent
            .get(&self.object_url())
            .set("Authorization", &self.auth_header())
            .call()
            .map_err(|e| VaultError::Sync(format!("GET object: {e}")))?;

        let mut compressed = Vec::new();
        resp.into_reader()
            .read_to_end(&mut compressed)
            .map_err(|e| VaultError::Io(e))?;

        let data = decompress(&compressed)?;

        // Verify integrity before touching the live vault file
        let actual_hash: [u8; 32] = *blake3::hash(&data).as_bytes();
        if actual_hash != *expected_hash {
            return Err(VaultError::Sync(
                "download integrity check failed: BLAKE3 mismatch".into(),
            ));
        }

        if conflict {
            // Write the remote version alongside the vault as a conflict file
            let mut cp = vault_path.to_path_buf();
            let stem = cp.file_stem().map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "vault".into());
            cp.set_file_name(format!("{stem}.conflict.{}", now_secs()));
            std::fs::write(&cp, &data).map_err(VaultError::Io)?;
            return Ok(true);
        }

        // Atomic replace: write to tmp, then rename
        let tmp = vault_path.with_extension("tmp");
        std::fs::write(&tmp, &data).map_err(VaultError::Io)?;
        std::fs::rename(&tmp, vault_path).map_err(VaultError::Io)?;
        Ok(false)
    }
}

fn parse_blake3_hex(s: &str) -> Result<[u8; 32], VaultError> {
    let bytes = hex::decode(s)
        .map_err(|_| VaultError::Sync("invalid blake3 hex in remote metadata".into()))?;
    bytes.try_into()
        .map_err(|_| VaultError::Sync("blake3 remote hash is not 32 bytes".into()))
}

struct RemoteInfo {
    blake3: [u8; 32],
    uploaded_at: u64,
    local_modified_at: u64,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn file_blake3_is_deterministic() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"vault data goes here").unwrap();
        let h1 = file_blake3(f.path()).unwrap();
        let h2 = file_blake3(f.path()).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn file_blake3_differs_for_different_content() {
        let mut f1 = NamedTempFile::new().unwrap();
        let mut f2 = NamedTempFile::new().unwrap();
        f1.write_all(b"content A").unwrap();
        f2.write_all(b"content B").unwrap();
        let h1 = file_blake3(f1.path()).unwrap();
        let h2 = file_blake3(f2.path()).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let data = b"SQLite encrypted vault file contents ... ".repeat(1000);
        let compressed = compress(&data).unwrap();
        let recovered = decompress(&compressed).unwrap();
        assert_eq!(data.to_vec(), recovered);
        assert!(compressed.len() < data.len(), "compression should reduce size");
    }

    #[test]
    fn missing_file_blake3_errors() {
        let result = file_blake3(Path::new("/nonexistent/vault.db"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_blake3_hex_valid() {
        let bytes = [0xABu8; 32];
        let hex = hex::encode(bytes);
        assert_eq!(parse_blake3_hex(&hex).unwrap(), bytes);
    }

    #[test]
    fn parse_blake3_hex_invalid_length() {
        assert!(parse_blake3_hex("aabbcc").is_err());
    }

    #[test]
    fn parse_blake3_hex_invalid_chars() {
        assert!(parse_blake3_hex(&"ZZ".repeat(32)).is_err());
    }
}
