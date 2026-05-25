//! Key Encapsulation Mechanism (KEM) for VMK backup copies.
//!
//! NOTE: The X448 + ML-KEM-1024 hybrid combiner used here is a transitional
//! construction.  ML-KEM-1024 alone is standardised in NIST FIPS 203 (Aug 2024).

use zeroize::ZeroizeOnDrop;

/// A 32-byte shared secret that zeroizes on drop.
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secret_as_bytes() {
        let ss = SharedSecret([0u8; 32]);
        assert_eq!(ss.as_bytes(), &[0u8; 32]);
    }
}
