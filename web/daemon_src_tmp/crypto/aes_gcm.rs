//! AES-256-GCM AEAD — inner double-encryption layer for OTP secrets and
//! classified credential fields (architecture §4, §12 CSfC path).
//!
//! This module mirrors `xchacha20.rs` in shape.  The outer layer
//! (XChaCha20-Poly1305) provides the 192-bit nonce and post-quantum safety;
//! the inner layer (AES-256-GCM) satisfies FIPS 140-3 / NSA CSfC requirements
//! for a second independent approved algorithm.

use aes_gcm::{
    aead::{AeadCore, KeyInit, OsRng, Payload, Aead},
    Aes256Gcm, Nonce,
};
use crate::error::VaultError;

pub const NONCE_LEN: usize = 12;

/// Encrypt `plaintext` with AES-256-GCM.
/// A fresh random 96-bit nonce is generated for each call.
/// Returns `(ciphertext_with_tag, nonce)`.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8])
    -> Result<(Vec<u8>, [u8; NONCE_LEN]), VaultError>
{
    let cipher = Aes256Gcm::new(key.into());
    let nonce  = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| VaultError::Crypto("aes-gcm encrypt failed".into()))?;
    Ok((ct, nonce.into()))
}

/// Decrypt `ciphertext` (with trailing 16-byte GCM tag) using AES-256-GCM.
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8])
    -> Result<Vec<u8>, VaultError>
{
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| VaultError::Crypto("aes-gcm decrypt failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [0x01u8; 32];
        let (ct, nonce) = encrypt(&key, b"classified vault data", b"aad").unwrap();
        assert_eq!(decrypt(&key, &ct, &nonce, b"aad").unwrap(), b"classified vault data");
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [0x02u8; 32];
        let (ct, nonce) = encrypt(&key, b"secret", b"good-aad").unwrap();
        assert!(decrypt(&key, &ct, &nonce, b"bad-aad").is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [0x03u8; 32];
        let key2 = [0x04u8; 32];
        let (ct, nonce) = encrypt(&key1, b"data", b"").unwrap();
        assert!(decrypt(&key2, &ct, &nonce, b"").is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let key = [0x05u8; 32];
        let (_, n1) = encrypt(&key, b"a", b"").unwrap();
        let (_, n2) = encrypt(&key, b"a", b"").unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn ciphertext_is_larger_than_plaintext() {
        // AES-256-GCM appends a 16-byte auth tag
        let key = [0x06u8; 32];
        let pt = b"hello";
        let (ct, _) = encrypt(&key, pt, b"").unwrap();
        assert_eq!(ct.len(), pt.len() + 16);
    }
}


#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_aead_roundtrip(
            key in any::<[u8; 32]>(),
            plaintext in proptest::collection::vec(any::<u8>(), 0..1024),
            aad in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            if let Ok((ciphertext, nonce)) = encrypt(&key, &plaintext, &aad) {
                let decrypted = decrypt(&key, &ciphertext, &nonce, &aad).expect("decryption failed");
                prop_assert_eq!(plaintext, decrypted);
            }
        }
    }
}
