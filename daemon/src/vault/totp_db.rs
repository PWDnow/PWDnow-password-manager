use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;
use argon2::{Argon2, Algorithm, Version, Params, PasswordVerifier};
use argon2::password_hash::{PasswordHash, PasswordHasher, SaltString};

use crate::crypto::{aes_gcm, xchacha20};
use crate::error::VaultError;
use crate::auth::totp;

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpConfig {
    pub id: String,
    pub secret_b32: String,
    pub created_at: i64,
}

#[derive(Debug)]
pub struct TotpSetupInfo {
    pub secret_b32: String,
    pub otp_uri: String,
    pub backup_codes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct BackupCode {
    hash: String,
    used_at: Option<i64>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ── CRUD ──────────────────────────────────────────────────────────────────────

pub fn is_active(conn: &Connection) -> bool {
    conn.query_row(
        "SELECT count(*) FROM otp_config",
        [],
        |r| r.get::<_, u32>(0),
    ).unwrap_or(0) > 0
}

pub fn begin_setup(
    conn: &Connection,
    vmk: &[u8; 32],
    account_label: &str,
    issuer: &str,
) -> Result<TotpSetupInfo, VaultError> {
    let mut secret_b32 = totp::generate_secret();
    let algorithm = "SHA512";
    let digits = 8;

    let otp_uri = format!(
        "otpauth://totp/{issuer}:{account_label}?secret={secret_b32}&issuer={issuer}&algorithm={algorithm}&digits={digits}&period=30"
    );

    // Use AES-256-GCM
    let (ciphertext, nonce) = aes_gcm::encrypt(vmk, secret_b32.as_bytes(), b"totp-secret-aad-v1")?;
    let (backup_ct, backup_nonce, backup_codes) = {
        let (codes, ct, n) = generate_backup_codes(vmk)?;
        (ct, n, codes)
    };

    let id = Uuid::new_v4().to_string();
    conn.execute("DELETE FROM otp_config", [])?;
    conn.execute(
        "INSERT INTO otp_config
             (id, encrypted_secret, secret_nonce, backup_codes, backup_nonce, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, ciphertext, nonce.as_slice(), backup_ct, backup_nonce, now()],
    )?;
    
    conn.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('totp_algorithm', ?1)", params![algorithm])?;
    conn.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('totp_digits', ?1)", params![digits as i64])?;
    
    set_confirmed(conn, false)?;

    let info = TotpSetupInfo { secret_b32: secret_b32.clone(), otp_uri, backup_codes };
    secret_b32.zeroize();
    Ok(info)
}

pub fn confirm_setup(conn: &Connection, vmk: &[u8; 32], code: &str) -> Result<(), VaultError> {
    if verify_code(conn, vmk, code)? {
        set_confirmed(conn, true)?;
        Ok(())
    } else {
        Err(VaultError::Auth("invalid code".into()))
    }
}

pub fn remove(conn: &Connection, vmk: &[u8; 32], code: &str) -> Result<(), VaultError> {
    if verify_code(conn, vmk, code)? {
        conn.execute("DELETE FROM otp_config", [])?;
        conn.execute("DELETE FROM vault_meta WHERE key IN ('totp_algorithm', 'totp_digits')", [])?;
        Ok(())
    } else {
        Err(VaultError::Auth("invalid code".into()))
    }
}

pub fn verify_code(conn: &Connection, vmk: &[u8; 32], code: &str) -> Result<bool, VaultError> {
    let config = load(conn, vmk)?;
    let (algo, digits) = get_params(conn);
    Ok(totp::verify(&config.secret_b32, code, algo, digits)?)
}

pub fn verify_backup_code(
    conn: &Connection,
    vmk: &[u8; 32],
    code: &str,
) -> Result<bool, VaultError> {
    let (backup_ct, nonce_vec): (Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT backup_codes, backup_nonce FROM otp_config LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).map_err(|_| VaultError::Auth("no TOTP config stored".into()))?;

    let json = match nonce_vec.len() {
        12 => {
            let nonce: [u8; 12] = nonce_vec.try_into().unwrap();
            aes_gcm::decrypt(vmk, &backup_ct, &nonce, b"totp-backup-aad-v1")?
        }
        24 => {
            let nonce: [u8; 24] = nonce_vec.try_into().unwrap();
            xchacha20::decrypt(vmk, &backup_ct, &nonce, b"totp-backup-aad-v1")?
        }
        _ => return Err(VaultError::Crypto("invalid backup nonce length".into())),
    };

    let mut records: Vec<BackupCode> = serde_json::from_slice(&json)
        .map_err(|e| VaultError::Crypto(format!("backup codes deserialize: {e}")))?;

    let params = Params::new(64 * 1024, 2, 2, None)
        .map_err(|e| VaultError::Crypto(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    for record in records.iter_mut() {
        if record.used_at.is_some() { continue; }
        let parsed_hash = PasswordHash::new(&record.hash)
            .map_err(|e| VaultError::Crypto(format!("parse backup hash: {e}")))?;
        if argon2.verify_password(code.as_bytes(), &parsed_hash).is_ok() {
            record.used_at = Some(now());
            let updated_json = serde_json::to_vec(&records).unwrap();
            let (new_ct, new_nonce) = aes_gcm::encrypt(vmk, &updated_json, b"totp-backup-aad-v1")?;
            conn.execute(
                "UPDATE otp_config SET backup_codes = ?1, backup_nonce = ?2",
                params![new_ct, new_nonce.as_slice()],
            )?;
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn load(conn: &Connection, vmk: &[u8; 32]) -> Result<TotpConfig, VaultError> {
    let (id, ciphertext, nonce_vec): (String, Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT id, encrypted_secret, secret_nonce FROM otp_config LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).map_err(|_| VaultError::Auth("no TOTP config stored".into()))?;

    let mut plaintext = match nonce_vec.len() {
        12 => {
            let nonce: [u8; 12] = nonce_vec.try_into().unwrap();
            aes_gcm::decrypt(vmk, &ciphertext, &nonce, b"totp-secret-aad-v1")?
        }
        24 => {
            let nonce: [u8; 24] = nonce_vec.try_into().unwrap();
            xchacha20::decrypt(vmk, &ciphertext, &nonce, b"totp-secret-aad-v1")?
        }
        _ => return Err(VaultError::Crypto("invalid totp nonce length".into())),
    };

    let secret_b32 = String::from_utf8(plaintext.clone())
        .map_err(|_| VaultError::Crypto("TOTP secret is not valid UTF-8".into()))?;
    plaintext.zeroize();

    Ok(TotpConfig { id, secret_b32, created_at: 0 })
}

pub fn get_params(conn: &Connection) -> (totp_rs::Algorithm, usize) {
    let algo_str = conn.query_row(
        "SELECT value FROM vault_meta WHERE key = 'totp_algorithm'",
        [],
        |r| r.get::<_, String>(0),
    ).unwrap_or("SHA512".into());
    
    let digits = conn.query_row(
        "SELECT value FROM vault_meta WHERE key = 'totp_digits'",
        [],
        |r| r.get::<_, i64>(0),
    ).unwrap_or(8) as usize;
    
    let algo = match algo_str.as_str() {
        "SHA512" => totp_rs::Algorithm::SHA512,
        _ => totp_rs::Algorithm::SHA512,
    };
    
    (algo, digits)
}

fn set_confirmed(conn: &Connection, active: bool) -> Result<(), VaultError> {
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('totp_active', ?1)",
        params![if active { 1 } else { 0 }],
    )?;
    Ok(())
}

fn generate_backup_codes(vmk: &[u8; 32]) -> Result<(Vec<String>, Vec<u8>, Vec<u8>), VaultError> {
    let mut codes = Vec::new();
    let mut records = Vec::new();

    // #19-FIX: use ≥50 bits of entropy (10 random bytes → 16-char Base32, ~80 bits)
    // instead of the former 32-bit u32 hex. Bump Argon2 to MIN_M_COST / MIN_T_COST.
    let params = Params::new(256 * 1024, 3, 1, None).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    use rand_core::RngCore;

    for _ in 0..10 {
        let mut raw = [0u8; 10];
        rand_core::OsRng.fill_bytes(&mut raw);
        // Encode 10 bytes as 16-char base32 (80 bits → 16 × 5-bit groups).
        let mut code = String::with_capacity(16);
        let mut buf: u64 = 0;
        let mut bits: u32 = 0;
        for &b in &raw {
            buf = (buf << 8) | (b as u64);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                let idx = ((buf >> bits) & 0x1F) as usize;
                code.push(BASE32_ALPHABET[idx] as char);
            }
        }
        // Flush remaining bits
        if bits > 0 {
            let idx = ((buf << (5 - bits)) & 0x1F) as usize;
            code.push(BASE32_ALPHABET[idx] as char);
        }
        let salt = SaltString::generate(&mut rand_core::OsRng);
        let hash = argon2.hash_password(code.as_bytes(), &salt)
            .map_err(|_| VaultError::Crypto("backup code hash failed".into()))?.to_string();
        codes.push(code);
        records.push(BackupCode { hash, used_at: None });
    }

    let json = serde_json::to_vec(&records).unwrap();
    let (ct, nonce) = aes_gcm::encrypt(vmk, &json, b"totp-backup-aad-v1")?;
    Ok((codes, ct, nonce.to_vec()))
}
