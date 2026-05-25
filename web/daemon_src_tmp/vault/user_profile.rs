//! User profile CRUD — name, email, and profile picture.
//!
//! All PII is encrypted at the application level with AES-256-GCM(VMK)
//! for NIST Level 5 compliance.

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::crypto::{aes_gcm, xchacha20};
use crate::error::VaultError;

const MAX_IMAGE_BYTES: usize = 2 * 1024 * 1024; // 2 MiB
const PROFILE_PIC_AAD: &[u8] = b"profile-pic-aad-v1";
const PROFILE_DATA_AAD: &[u8] = b"profile-data-aad-v1";

/// Plaintext profile data returned to the client.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileData {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    /// Raw image bytes (PNG, already stripped of EXIF), or absent if not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_pic: Option<Vec<u8>>,
    /// Unix timestamp of the last master password change.
    pub password_changed_at: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedProfileFields {
    first_name: String,
    last_name: String,
    email: String,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ── Read ──────────────────────────────────────────────────────────────────────

/// Load the profile for the first user in the vault.
pub fn get(conn: &Connection, vmk: &[u8; 32]) -> Result<Option<ProfileData>, VaultError> {
    let row: rusqlite::Result<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> = conn.query_row(
        "SELECT ciphertext, nonce, profile_pic FROM users LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    );

    let password_changed_at: Option<u64> = conn.query_row(
        "SELECT value FROM vault_meta WHERE key = 'password_changed_at'",
        [],
        |r| r.get(0),
    ).ok();

    match row {
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
        Ok((ct_opt, nonce_opt, pic_blob)) => {
            let (first_name, last_name, email) = if let (Some(c), Some(n)) = (ct_opt, nonce_opt) {
                let fields = decrypt_profile_fields(vmk, &c, &n)?;
                (fields.first_name, fields.last_name, fields.email)
            } else {
                ("".to_string(), "".to_string(), "".to_string())
            };

            let profile_pic = if let Some(blob) = pic_blob {
                Some(decrypt_pic(vmk, &blob)?)
            } else {
                None
            };
            
            Ok(Some(ProfileData { 
                first_name, 
                last_name, 
                email, 
                profile_pic,
                password_changed_at,
            }))
        }
    }
}

// ── Write ─────────────────────────────────────────────────────────────────────

/// Insert or update the user profile.
pub fn update(
    conn: &Connection,
    vmk: &[u8; 32],
    first_name: &str,
    last_name: &str,
    email: &str,
) -> Result<(), VaultError> {
    let fields = EncryptedProfileFields {
        first_name: first_name.to_string(),
        last_name: last_name.to_string(),
        email: email.to_string(),
    };
    let (ct, nonce) = encrypt_profile_fields(vmk, &fields)?;

    conn.execute(
        "INSERT INTO users (id, ciphertext, nonce, created_at)
         VALUES ('profile', ?1, ?2, ?3)
         ON CONFLICT(id) DO UPDATE SET
             ciphertext = excluded.ciphertext,
             nonce      = excluded.nonce",
        params![ct, nonce, now()],
    )?;
    Ok(())
}

/// Clear the stored profile picture. Idempotent — succeeds when no row or no
/// picture is present. Other profile fields (name, email) are untouched.
pub fn remove_picture(conn: &Connection) -> Result<(), VaultError> {
    conn.execute(
        "UPDATE users SET profile_pic = NULL WHERE id = 'profile'",
        [],
    )?;
    Ok(())
}

/// Validate, EXIF-strip, and store a profile picture.
pub fn upload_picture(
    conn: &Connection,
    vmk: &[u8; 32],
    image_bytes: &[u8],
) -> Result<(), VaultError> {
    if image_bytes.len() > MAX_IMAGE_BYTES {
        return Err(VaultError::Ipc(format!(
            "image too large: {} bytes (max {})",
            image_bytes.len(),
            MAX_IMAGE_BYTES,
        )));
    }
    validate_magic(image_bytes)?;

    // M-27 fix: use image::ImageReader with strict limits to prevent pixel-bomb DoS.
    use std::io::Cursor;
    let mut reader = image::ImageReader::new(Cursor::new(image_bytes));
    reader.set_format(if image_bytes[0] == 0x89 { image::ImageFormat::Png } else { image::ImageFormat::Jpeg });
    
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(2048); // 2k pixels
    limits.max_image_height = Some(2048);
    limits.max_alloc = Some(16 * 1024 * 1024); // 16 MiB max work RAM
    reader.limits(limits);
    
    let img = reader.decode()
        .map_err(|e| VaultError::Crypto(format!("image decode with limits: {e}")))?;

    let mut png_buf: Vec<u8> = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut png_buf), image::ImageFormat::Png)
        .map_err(|e| VaultError::Crypto(format!("image re-encode: {e}")))?;

    let encrypted = encrypt_pic(vmk, &png_buf)?;
    conn.execute(
        "INSERT INTO users (id, ciphertext, nonce, profile_pic, created_at)
         VALUES ('profile', NULL, NULL, ?1, ?2)
         ON CONFLICT(id) DO UPDATE SET profile_pic = excluded.profile_pic",
        params![encrypted, now()],
    )?;
    Ok(())
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

fn encrypt_profile_fields(vmk: &[u8; 32], fields: &EncryptedProfileFields) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    let json = serde_json::to_vec(fields)
        .map_err(|e| VaultError::Crypto(format!("profile serialize: {e}")))?;
    let (ct, nonce) = aes_gcm::encrypt(vmk, &json, PROFILE_DATA_AAD)?;
    Ok((ct, nonce.to_vec()))
}

fn decrypt_profile_fields(vmk: &[u8; 32], ct: &[u8], nonce_bytes: &[u8]) -> Result<EncryptedProfileFields, VaultError> {
    let json = match nonce_bytes.len() {
        12 => {
            let nonce: [u8; 12] = nonce_bytes.try_into().unwrap();
            aes_gcm::decrypt(vmk, ct, &nonce, PROFILE_DATA_AAD)?
        }
        24 => {
            let nonce: [u8; 24] = nonce_bytes.try_into().unwrap();
            xchacha20::decrypt(vmk, ct, &nonce, PROFILE_DATA_AAD)?
        }
        _ => return Err(VaultError::Crypto("invalid profile nonce length".into())),
    };
    serde_json::from_slice(&json)
        .map_err(|e| VaultError::Crypto(format!("profile deserialize: {e}")))
}

const PIC_VERSION_AES_GCM: u8 = 0xA1;
const PIC_VERSION_XCHACHA: u8 = 0xC2;

fn encrypt_pic(vmk: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, VaultError> {
    let (ct, nonce) = aes_gcm::encrypt(vmk, data, PROFILE_PIC_AAD)?;
    // M-10 fix: use explicit version byte instead of just nonce length.
    let mut blob = Vec::with_capacity(1 + 12 + ct.len());
    blob.push(PIC_VERSION_AES_GCM);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

fn decrypt_pic(vmk: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, VaultError> {
    if blob.is_empty() { return Err(VaultError::Crypto("empty pic blob".into())); }
    
    match blob[0] {
        PIC_VERSION_AES_GCM => {
            if blob.len() < 13 { return Err(VaultError::Crypto("pic blob too short".into())); }
            let nonce: [u8; 12] = blob[1..13].try_into().unwrap();
            let ct = &blob[13..];
            aes_gcm::decrypt(vmk, ct, &nonce, PROFILE_PIC_AAD)
        }
        PIC_VERSION_XCHACHA => {
            if blob.len() < 25 { return Err(VaultError::Crypto("pic blob too short".into())); }
            let nonce: [u8; 24] = blob[1..25].try_into().unwrap();
            let ct = &blob[25..];
            xchacha20::decrypt(vmk, ct, &nonce, PROFILE_PIC_AAD)
        }
        _ => {
            // M-10 legacy fallback: previous version used nonce length (12 or 24) as first byte.
            let nonce_len = blob[0] as usize;
            if nonce_len == 12 {
                if blob.len() < 13 { return Err(VaultError::Crypto("legacy pic blob too short".into())); }
                let nonce: [u8; 12] = blob[1..13].try_into().unwrap();
                let ct = &blob[13..];
                aes_gcm::decrypt(vmk, ct, &nonce, PROFILE_PIC_AAD)
            } else if nonce_len == 24 || (blob.len() >= 24 && nonce_len != 12) {
                // If it looks like a 24-byte nonce || ct
                let nonce_bytes = if nonce_len == 24 { &blob[1..25] } else { &blob[0..24] };
                let ct = if nonce_len == 24 { &blob[25..] } else { &blob[24..] };
                let nonce: [u8; 24] = nonce_bytes.try_into().unwrap();
                xchacha20::decrypt(vmk, ct, &nonce, PROFILE_PIC_AAD)
            } else {
                Err(VaultError::Crypto("unsupported pic encryption format".into()))
            }
        }
    }
}

// ── Magic-byte validation ─────────────────────────────────────────────────────

fn validate_magic(data: &[u8]) -> Result<(), VaultError> {
    if data.len() < 4 {
        return Err(VaultError::Ipc("image data too short".into()));
    }
    let is_jpeg = data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF;
    let is_png  = data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47;
    if !is_jpeg && !is_png {
        return Err(VaultError::Ipc("unsupported image format (JPEG or PNG only)".into()));
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use crate::vault::db::open_vault;

    fn open() -> (NamedTempFile, Connection) {
        let f = NamedTempFile::new().unwrap();
        let c = open_vault(f.path(), &[0xAAu8; 32]).unwrap();
        (f, c)
    }

    const VMK: [u8; 32] = [0x55u8; 32];

    #[test]
    fn get_returns_none_on_empty_vault() {
        let (_f, c) = open();
        assert!(get(&c, &VMK).unwrap().is_none());
    }

    #[test]
    fn update_then_get_roundtrip() {
        let (_f, c) = open();
        update(&c, &VMK, "Alice", "Smith", "alice@vault.local").unwrap();
        let profile = get(&c, &VMK).unwrap().unwrap();
        assert_eq!(profile.first_name, "Alice");
    }
}
