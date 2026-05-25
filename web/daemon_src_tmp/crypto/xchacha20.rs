use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use crate::error::VaultError;

pub const NONCE_LEN: usize = 24;

pub fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8])
    -> Result<(Vec<u8>, [u8; NONCE_LEN]), VaultError>
{
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce  = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher.encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| VaultError::Crypto("encrypt failed".into()))?;
    Ok((ct, nonce.into()))
}

pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8])
    -> Result<Vec<u8>, VaultError>
{
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher.decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| VaultError::Crypto("decrypt failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [0x01u8; 32];
        let (ct, nonce) = encrypt(&key, b"hello vault", b"aad").unwrap();
        assert_eq!(decrypt(&key, &ct, &nonce, b"aad").unwrap(), b"hello vault");
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [0x02u8; 32];
        let (ct, nonce) = encrypt(&key, b"secret", b"good").unwrap();
        assert!(decrypt(&key, &ct, &nonce, b"bad").is_err());
    }

    #[test]
    fn nonces_unique() {
        let key = [0x03u8; 32];
        let (_, n1) = encrypt(&key, b"a", b"").unwrap();
        let (_, n2) = encrypt(&key, b"a", b"").unwrap();
        assert_ne!(n1, n2);
    }
}
