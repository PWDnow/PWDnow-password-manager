use hmac::{Hmac, Mac};
use sha2::Sha512;
use crate::error::VaultError;

type HmacSha512 = Hmac<Sha512>;

/// Compute a blind index (HMAC-SHA512) for a searchable field.
/// Returns hex-encoded hash.
pub fn compute(key: &[u8; 64], value: &str) -> Result<String, VaultError> {
    let mut mac = HmacSha512::new_from_slice(key)
        .map_err(|_| VaultError::Crypto("invalid blind index key length".into()))?;
    mac.update(value.as_bytes());
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blind_index_consistency() {
        let key = [0x42u8; 64];
        let h1 = compute(&key, "github.com").unwrap();
        let h2 = compute(&key, "github.com").unwrap();
        let h3 = compute(&key, "google.com").unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }
}
