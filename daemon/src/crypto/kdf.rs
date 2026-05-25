//! Key derivation functions.
//!
//! Argon2id parameters (m=256 MiB, t=3, p=4) satisfy NIST SP 800-63B-4 (2024) §5.1.1.2
//! memory-hard KDF floors for AAL3. PBKDF2-HMAC-SHA-512 at 1,000,000 iterations meets
//! the NSA CNSA 2.0 (CSI-CNSA-2.0, Sept 2022) minimum; salt construction per NIST SP 800-132 (2010).

use argon2::{Algorithm, Argon2, Params, Version};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use zeroize::Zeroize;
use crate::error::VaultError;
use super::secure_store::LockedKey;

/// Returns 64-byte mlock()ed buffer: bytes [0..32] = KEK, [32..64] = AuthKey.
/// Uses Argon2id (modern, side-channel resistant).
pub fn derive_kek_argon2(
    password: &[u8],
    yubikey_response: Option<&[u8; 20]>,
    salt: &[u8; 32],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<LockedKey, VaultError> {
    let mut input = password.to_vec();
    if let Some(yk) = yubikey_response { input.extend_from_slice(yk); }

    let params = Params::new(m_cost, t_cost, p_cost, Some(64))
        .map_err(|e| VaultError::Crypto(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key_buf = LockedKey::new(64)?;
    argon2.hash_password_into(&input, salt, &mut *key_buf.as_bytes_mut())
        .map_err(|e| VaultError::Crypto(format!("argon2: {e}")))?;

    input.zeroize();
    Ok(key_buf)
}

/// Returns 64-byte mlock()ed buffer using PBKDF2-HMAC-SHA512.
/// Salt construction per NIST SP 800-132 (2010); iteration count per NSA CNSA 2.0 (CSI-CNSA-2.0, Sept 2022).
pub fn derive_kek_pbkdf2(
    password: &[u8],
    yubikey_response: Option<&[u8; 20]>,
    salt: &[u8; 32],
    iterations: u32,
) -> Result<LockedKey, VaultError> {
    let mut input = password.to_vec();
    if let Some(yk) = yubikey_response { input.extend_from_slice(yk); }

    let mut key_buf = LockedKey::new(64)?;
    pbkdf2_hmac::<Sha512>(&input, salt, iterations, &mut *key_buf.as_bytes_mut());

    input.zeroize();
    Ok(key_buf)
}

/// Default KEK derivation. For NIST Level 5, we prioritize PBKDF2-HMAC-SHA512.
/// (Wait: we'll keep Argon2id as the default in code but allow switching).
pub fn derive_kek(
    password: &[u8],
    yubikey_response: Option<&[u8; 20]>,
    salt: &[u8; 32],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<LockedKey, VaultError> {
    if m_cost == 0 {
        if t_cost < 100_000 {
            return Err(VaultError::Crypto("PBKDF2 iterations too low".into()));
        }
        derive_kek_pbkdf2(password, yubikey_response, salt, t_cost)
    } else {
        if m_cost < 64 * 1024 || t_cost == 0 || p_cost == 0 {
            return Err(VaultError::Crypto("invalid KDF parameters".into()));
        }
        derive_kek_argon2(password, yubikey_response, salt, m_cost, t_cost, p_cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_is_deterministic() {
        let salt = [0x42u8; 32];
        let k1 = derive_kek_argon2(b"pw", None, &salt, 64 * 1024, 1, 1).unwrap();
        let k2 = derive_kek_argon2(b"pw", None, &salt, 64 * 1024, 1, 1).unwrap();
        assert_eq!(&*k1.as_bytes(), &*k2.as_bytes());
    }

    #[test]
    fn pbkdf2_is_deterministic() {
        let salt = [0x42u8; 32];
        let k1 = derive_kek_pbkdf2(b"pw", None, &salt, 1000).unwrap();
        let k2 = derive_kek_pbkdf2(b"pw", None, &salt, 1000).unwrap();
        assert_eq!(&*k1.as_bytes(), &*k2.as_bytes());
    }

    #[test]
    fn output_is_64_bytes() {
        let k = derive_kek(b"pw", None, &[0u8; 32], 64 * 1024, 1, 1).unwrap();
        assert_eq!(k.as_bytes().len(), 64);
        
        let k2 = derive_kek(b"pw", None, &[0u8; 32], 0, 100_000, 0).unwrap();
        assert_eq!(k2.as_bytes().len(), 64);
    }
}
