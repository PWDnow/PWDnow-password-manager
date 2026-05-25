// FIPS 140-3 §AS09 Power-On Self-Tests (POST).
//
// Runs one Known-Answer Test (KAT) per approved primitive before the daemon
// advertises readiness to systemd. On failure the process exits with code 42
// which matches `RestartForceExitStatus=42` in the service unit — systemd will
// NOT auto-restart, alerting the operator to a broken build.
//
// Primitives tested: AES-256-GCM, HMAC-SHA-512, PBKDF2-HMAC-SHA-512,
// HKDF-SHA-384, SHA3-512.  ML-KEM-1024 and ML-DSA-87 KATs are skipped at
// compile time unless the `pq` feature is enabled (the crates are optional).

use crate::error::VaultError;

/// Run all power-on self-tests. Returns Err if any KAT fails.
pub fn run_post() -> Result<(), VaultError> {
    kat_aes_256_gcm()?;
    kat_hmac_sha512()?;
    kat_pbkdf2_hmac_sha512()?;
    kat_hkdf_sha384()?;
    kat_sha3_512()?;
    Ok(())
}

// ── AES-256-GCM KAT (NIST SP 800-38D Test Case 13 — empty PT, tag-only output)
fn kat_aes_256_gcm() -> Result<(), VaultError> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, generic_array::GenericArray}};

    // NIST SP 800-38D Appendix B Test Case 13:
    // K=0...0 (256-bit), IV=0...0 (96-bit), PT=empty, AAD=empty → Tag only output.
    let key = [0u8; 32];
    let iv  = [0u8; 12];
    // aes-gcm crate appends the 16-byte auth tag; for empty PT output is tag only.
    let expected_tag = hex::decode("530f8afbc74536b9a963b4f1c4cb738b").unwrap();

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let nonce  = GenericArray::from_slice(&iv);
    let ct = cipher.encrypt(nonce, b"".as_ref())
        .map_err(|_| VaultError::Crypto("POST: AES-256-GCM encrypt failed".into()))?;

    if ct != expected_tag {
        return Err(VaultError::Crypto("POST: AES-256-GCM KAT mismatch".into()));
    }

    // Verify round-trip: decrypt the tag-only ciphertext back to empty plaintext
    let dec = cipher.decrypt(nonce, ct.as_slice())
        .map_err(|_| VaultError::Crypto("POST: AES-256-GCM decrypt failed".into()))?;
    if !dec.is_empty() {
        return Err(VaultError::Crypto("POST: AES-256-GCM round-trip mismatch".into()));
    }

    // Tamper detection: a modified tag must fail authentication
    let mut tampered = ct.clone();
    tampered[0] ^= 0x01;
    if cipher.decrypt(nonce, tampered.as_slice()).is_ok() {
        return Err(VaultError::Crypto("POST: AES-256-GCM tamper detection failed".into()));
    }
    Ok(())
}

// ── HMAC-SHA-512 KAT (RFC 4231 Test Case 1) ─────────────────────────────────
fn kat_hmac_sha512() -> Result<(), VaultError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;
    let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let msg = b"Hi There";
    let expected = hex::decode(
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cd\
         edaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    ).unwrap();

    let mut mac = HmacSha512::new_from_slice(&key).unwrap();
    mac.update(msg);
    let result = mac.finalize().into_bytes();

    if result.as_slice() != expected.as_slice() {
        return Err(VaultError::Crypto("POST: HMAC-SHA-512 KAT mismatch".into()));
    }
    Ok(())
}

// ── PBKDF2-HMAC-SHA-512 KAT (RFC 6070-like, SHA-512 variant) ────────────────
fn kat_pbkdf2_hmac_sha512() -> Result<(), VaultError> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha512;

    let password = b"password";
    let salt     = b"salt";
    let iters    = 1u32;
    // Expected output computed from the standard PBKDF2-HMAC-SHA512 formulation
    let expected = hex::decode(
        "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252\
         c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"
    ).unwrap();

    let mut out = [0u8; 64];
    pbkdf2_hmac::<Sha512>(password, salt, iters, &mut out);

    if out.as_slice() != expected.as_slice() {
        return Err(VaultError::Crypto("POST: PBKDF2-HMAC-SHA-512 KAT mismatch".into()));
    }
    Ok(())
}

// ── HKDF-SHA-384 KAT (RFC 5869 Test Case 1, adapted to SHA-384) ─────────────
fn kat_hkdf_sha384() -> Result<(), VaultError> {
    use hkdf::Hkdf;
    use sha2::Sha384;

    let ikm  = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let expected = hex::decode(
        "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5"
    ).unwrap();
    let okm_len = expected.len(); // 42 bytes

    let hk = Hkdf::<Sha384>::new(Some(&salt), &ikm);
    let mut okm = vec![0u8; okm_len];
    hk.expand(&info, &mut okm)
        .map_err(|_| VaultError::Crypto("POST: HKDF-SHA-384 expand failed".into()))?;

    if okm != expected {
        return Err(VaultError::Crypto("POST: HKDF-SHA-384 KAT mismatch".into()));
    }
    Ok(())
}

// ── SHA3-512 KAT (NIST FIPS 202 short-message vector) ───────────────────────
fn kat_sha3_512() -> Result<(), VaultError> {
    use sha3::{Sha3_512, Digest};

    // NIST FIPS 202 Known-Answer: SHA3-512("abc")
    let expected = hex::decode(
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
         10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    ).unwrap();

    let mut h = Sha3_512::new();
    h.update(b"abc");
    let result = h.finalize();

    if result.as_slice() != expected.as_slice() {
        return Err(VaultError::Crypto("POST: SHA3-512 KAT mismatch".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_all_pass() {
        run_post().expect("FIPS 140-3 POST failed");
    }
}
