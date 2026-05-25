//! Signature infrastructure for PWDnow.
//!
//! Current: ML-DSA-87 (FIPS 204) for NIST Level 5 compliance.
//!
//! A one-byte `SigSuite` tag is prepended to every signature so recipients can
//! dispatch to the correct verifier without ambiguity.

use ml_dsa::{MlDsa87, VerifyingKey};
use ml_dsa::signature::Verifier;
use crate::error::VaultError;

/// One-byte suite identifier prepended to every signature blob.
#[repr(u8)]
pub enum SigSuite {
    /// Classical Ed25519, RFC 8032 (Legacy).
    Ed25519 = 0x01,
    /// ML-DSA-87 (FIPS 204), NIST Security Level 5.
    MlDsa87 = 0x02,
}

/// Verify a signature produced by `SignPair::sign`.
///
/// `verifying_key_bytes` is the raw bytes of the verifying key.
/// `sig_bytes` is `[suite_byte || signature]`.
pub fn verify(verifying_key_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<(), VaultError> {
    if sig_bytes.is_empty() {
        return Err(VaultError::Crypto("empty signature".into()));
    }
    match sig_bytes[0] {
        x if x == SigSuite::MlDsa87 as u8 => {
            let vk_bytes: &ml_dsa::EncodedVerifyingKey<MlDsa87> = verifying_key_bytes.try_into()
                .map_err(|_| VaultError::Crypto("invalid ML-DSA-87 verifying key length".into()))?;
            let vk = VerifyingKey::<MlDsa87>::decode(vk_bytes);
            
            let sig = ml_dsa::Signature::<MlDsa87>::try_from(&sig_bytes[1..])
                .map_err(|_| VaultError::Crypto("invalid ML-DSA-87 signature length".into()))?;
            
            vk.verify(message, &sig)
                .map_err(|_| VaultError::Crypto("ML-DSA-87 signature verification failed".into()))
        }
        x if x == SigSuite::Ed25519 as u8 => {
            // Legacy support for Ed25519 (Level 1)
            use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdVerifyingKey, Verifier as _};
            if sig_bytes.len() != 1 + 64 {
                return Err(VaultError::Crypto("Ed25519 signature must be 65 bytes".into()));
            }
            let sig_arr: &[u8; 64] = sig_bytes[1..].try_into().unwrap();
            let sig = EdSignature::from_bytes(sig_arr);
            let vk_bytes: &[u8; 32] = verifying_key_bytes.try_into()
                .map_err(|_| VaultError::Crypto("Ed25519 verifying key must be 32 bytes".into()))?;
            let vk = EdVerifyingKey::from_bytes(vk_bytes)
                .map_err(|_| VaultError::Crypto("invalid Ed25519 verifying key".into()))?;
            vk.verify(message, &sig)
                .map_err(|_| VaultError::Crypto("Ed25519 signature verification failed".into()))
        }
        other => Err(VaultError::Crypto(format!("unknown signature suite: 0x{other:02x}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{SigningKey, KeyGen, Signature};
    use ml_dsa::signature::{Signer, Keypair, SignatureEncoding};
    use rand_core::{OsRng, RngCore};

    /// A signing key pair.
    pub struct SignPair {
        signing: SigningKey<MlDsa87>,
    }

    impl SignPair {
        /// Generate a fresh ML-DSA-87 key pair.
        pub fn generate() -> Self {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            Self::from_seed(&seed)
        }

        /// Restore a signing key from a 32-byte seed.
        pub fn from_seed(seed: &[u8; 32]) -> Self {
            let seed_arr: [u8; 32] = *seed;
            Self { signing: MlDsa87::from_seed(&seed_arr.into()) }
        }

        /// Export the verifying (public) key.
        pub fn verifying_key(&self) -> Vec<u8> {
            self.signing.verifying_key().encode().to_vec()
        }

        /// Sign `message`. Returns `[suite_byte || signature]`.
        pub fn sign(&self, message: &[u8]) -> Vec<u8> {
            let sig: Signature<MlDsa87> = self.signing.sign(message);
            let sig_bytes = sig.to_bytes();
            let mut out = Vec::with_capacity(1 + sig_bytes.len());
            out.push(SigSuite::MlDsa87 as u8);
            out.extend_from_slice(sig_bytes.as_slice());
            out
        }
    }

    #[test]
    fn mldsa87_sign_verify_roundtrip() {
        let pair = SignPair::generate();
        let vk = pair.verifying_key();
        let msg = b"audit-log-root hash goes here";
        let sig = pair.sign(msg);
        assert_eq!(sig[0], SigSuite::MlDsa87 as u8);
        verify(&vk, msg, &sig).expect("valid ML-DSA-87 signature must verify");
    }

    #[test]
    fn mldsa87_tampered_message_rejected() {
        let pair = SignPair::generate();
        let vk = pair.verifying_key();
        let sig = pair.sign(b"original message");
        let result = verify(&vk, b"tampered message", &sig);
        assert!(result.is_err(), "tampered message must not verify");
    }

    #[test]
    fn mldsa87_wrong_key_rejected() {
        let pair = SignPair::generate();
        let other = SignPair::generate();
        let sig = pair.sign(b"message");
        let result = verify(&other.verifying_key(), b"message", &sig);
        assert!(result.is_err(), "wrong key must not verify");
    }
}
