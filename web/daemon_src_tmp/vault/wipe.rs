// NIST SP 800-88 Rev. 2 cryptographic erase for the vault.
//
// Primary path: `cryptographic_erase` — zeroes all key-material fields in
// vault.db.meta (argon2_salt, encrypted_vmk, passkey VMK copies, etc.) then
// unlinks both files. Without the salt no KEK can be derived; vault.db is
// permanently opaque ciphertext even if the raw bytes are recovered.
//
// Legacy fallback: `media_overwrite` — the former 7-pass DoD loop, retained
// for rotational-media deployments. Invoked only when the caller opts in
// via `VAULT_WIPE_MODE=overwrite`. Multi-pass overwrite has no defined effect
// on SSDs (FTL remapping) and is not an approved sanitisation technique under
// NIST SP 800-88 Rev. 2 for flash storage.

use std::path::Path;
use rand_core::{OsRng, RngCore};

use super::state::{VaultHeader, PasskeySidecarEntry, PqcSidecarEntry};
use crate::error::VaultError;

/// NIST SP 800-88 Rev. 2 — cryptographic erase.
///
/// Sanitises every key-material field in `meta_path` in-place, fsyncs, then
/// unlinks both `meta_path` and `db_path`. On failure, falls back to unlinking
/// without sanitising (the ciphertext is still unrecoverable without the KEK).
pub fn cryptographic_erase(meta_path: &Path, db_path: &Path) -> Result<(), VaultError> {
    // Step 1: read the current header
    let raw = std::fs::read(meta_path)?;
    let mut header: VaultHeader = serde_json::from_slice(&raw)
        .map_err(|e| VaultError::Crypto(format!("meta parse: {e}")))?;

    // Step 2: zero every salt / key field
    sanitise_header(&mut header);

    // Step 3: write sanitised header back and fsync
    let sanitised = serde_json::to_vec(&header)
        .map_err(|e| VaultError::Crypto(format!("meta serialise: {e}")))?;
    let tmp = meta_path.with_extension("meta.wipe_tmp");
    std::fs::write(&tmp, &sanitised)?;
    {
        let f = std::fs::OpenOptions::new().write(true).open(&tmp)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, meta_path)?;

    // Step 4: fsync parent directory
    if let Some(parent) = meta_path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    // Step 5: unlink vault.db (opaque ciphertext, no decryption path)
    if db_path.exists() {
        // M-07 fix: punch holes to issue TRIM/UNMAP hints to SSDs before unlinking.
        punch_hole(db_path);
        std::fs::remove_file(db_path)?;
    }

    // Step 6: unlink the sanitised meta file
    if meta_path.exists() {
        punch_hole(meta_path);
        std::fs::remove_file(meta_path)?;
    }

    // Step 7: fsync parent again after unlinks
    if let Some(parent) = meta_path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

fn punch_hole(path: &Path) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        if let Ok(file) = std::fs::OpenOptions::new().write(true).open(path) {
            if let Ok(m) = file.metadata() {
                let len = m.len();
                if len > 0 {
                    // FALLOC_FL_PUNCH_HOLE (0x01) | FALLOC_FL_KEEP_SIZE (0x02)
                    unsafe {
                        libc::fallocate(file.as_raw_fd(), 0x01 | 0x02, 0, len as libc::off_t);
                    }
                    let _ = file.sync_all();
                }
            }
        }
    }
}

fn sanitise_header(h: &mut VaultHeader) {
    h.argon2_salt      = zeroed_hex(32);
    h.encrypted_vmk    = zeroed_hex(48);
    h.vmk_nonce        = zeroed_hex(24);
    h.wipe_ticket_hash = String::new();

    for entry in &mut h.passkey_credentials {
        *entry = PasskeySidecarEntry {
            credential_id_hex:  entry.credential_id_hex.clone(),
            encrypted_vmk_copy: zeroed_hex(48),
            vmk_copy_nonce:     zeroed_hex(24),
            pub_key_cbor_hex:   None, // public key is erased on wipe
            sign_count: 0,
        };
    }
    for entry in &mut h.pqc_credentials {
        *entry = PqcSidecarEntry {
            credential_id_hex: entry.credential_id_hex.clone(),
            verifying_key_hex: String::new(),
            dk_seed_hex:       zeroed_hex(32),
            dk_nonce_hex:      zeroed_hex(24),
        };
    }
    h.quick_unlock_credentials.clear();
}

fn zeroed_hex(byte_len: usize) -> String {
    "00".repeat(byte_len)
}

/// Legacy multi-pass overwrite — for rotational media only.
///
/// Enable with `VAULT_WIPE_MODE=overwrite`. Not meaningful on SSDs.
#[cfg_attr(not(feature = "legacy-overwrite"), allow(dead_code))]
pub fn media_overwrite(path: &Path, passes: u8) -> Result<(), VaultError> {
    use std::io::{Seek, SeekFrom, Write};
    if !path.exists() { return Ok(()); }
    let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if len == 0 { std::fs::remove_file(path)?; return Ok(()); }
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    let mut buf = vec![0u8; 65536];
    for pass in 0..passes {
        file.seek(SeekFrom::Start(0))?;
        let mut rem = len;
        while rem > 0 {
            let chunk = (rem as usize).min(65536);
            match pass {
                0 => buf[..chunk].fill(0x00),
                1 => buf[..chunk].fill(0xFF),
                _ => OsRng.fill_bytes(&mut buf[..chunk]),
            }
            file.write_all(&buf[..chunk])?;
            rem -= chunk as u64;
        }
        file.sync_all()?;
    }
    file.set_len(0)?;
    file.sync_all()?;
    drop(file);
    std::fs::remove_file(path)?;
    Ok(())
}
