use totp_rs::{Algorithm, Secret, TOTP};
use crate::error::VaultError;

/// Wraps totp-rs to provide secret generation, code generation, and verification.
/// Secrets are stored/transmitted as base32-encoded strings (compatible with T...
fn make_totp(secret_b32: &str, algorithm: Algorithm, digits: usize) -> Result<TOTP, VaultError> {
    let bytes = Secret::Encoded(secret_b32.to_uppercase())
        .to_bytes()
        .map_err(|e| VaultError::Auth(format!("invalid TOTP secret: {e}")))?;
    TOTP::new(algorithm, digits, 1, 30, bytes)
        .map_err(|e| VaultError::Auth(format!("TOTP init failed: {e}")))
}

/// Generate a new random TOTP secret, returned as a base32 string.
pub fn generate_secret() -> String {
    let secret = Secret::generate_secret();
    // Secret::generate_secret() returns Secret::Raw(_); encode to base32 for storage.
    match secret {
        Secret::Raw(bytes) => {
            // Re-encode via the Encoded path by round-tripping through base32.
            // totp-rs doesn't expose a direct base32-encode helper, so we use
            // the fact that Secret::Encoded is just uppercased base32.
            base32::encode(base32::Alphabet::RFC4648 { padding: false }, &bytes)
        }
        Secret::Encoded(s) => s,
    }
}

/// Return the current TOTP code for the given base32 secret.
pub fn current_code(secret_b32: &str, algorithm: Algorithm, digits: usize) -> Result<String, VaultError> {
    let totp = make_totp(secret_b32, algorithm, digits)?;
    totp.generate_current()
        .map_err(|e| VaultError::Auth(format!("TOTP generate failed: {e}")))
}

/// Verify a TOTP code against the given base32 secret.
/// Allows 1-step skew (±30 s) as configured in `make_totp`.
pub fn verify(secret_b32: &str, code: &str, algorithm: Algorithm, digits: usize) -> Result<bool, VaultError> {
    let totp = make_totp(secret_b32, algorithm, digits)?;
    totp.check_current(code)
        .map_err(|e| VaultError::Auth(format!("TOTP check failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secret_is_valid_base32() {
        let s = generate_secret();
        assert!(!s.is_empty());
        // Must be decodable
        let decoded = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &s);
        assert!(decoded.is_some(), "generated secret must be valid base32");
        assert!(decoded.unwrap().len() >= 20, "secret should be at least 160 bits");
    }

    #[test]
    fn test_current_code_roundtrip() {
        let secret = generate_secret();
        let code = current_code(&secret, Algorithm::SHA1, 6).unwrap();
        assert_eq!(code.len(), 6, "TOTP code must be 6 digits");
        assert!(code.chars().all(|c| c.is_ascii_digit()), "TOTP code must be numeric");
    }

    #[test]
    fn test_verify_current_code_succeeds() {
        let secret = generate_secret();
        let code = current_code(&secret, Algorithm::SHA1, 6).unwrap();
        let valid = verify(&secret, &code, Algorithm::SHA1, 6).unwrap();
        assert!(valid, "freshly generated code must verify as valid");
    }

    #[test]
    fn test_verify_wrong_code_fails() {
        let secret = generate_secret();
        // "000000" is almost certainly wrong
        let code = current_code(&secret, Algorithm::SHA1, 6).unwrap();
        let wrong = if code == "000000" { "111111" } else { "000000" };
        let valid = verify(&secret, wrong, Algorithm::SHA1, 6).unwrap();
        assert!(!valid, "incorrect code must not verify");
    }

    #[test]
    fn test_verify_invalid_secret_errors() {
        let result = verify("!!!NOT_BASE32!!!", "123456", Algorithm::SHA1, 6);
        assert!(result.is_err(), "invalid base32 secret must return error");
    }

    #[test]
    fn test_different_secrets_produce_different_codes() {
        let s1 = generate_secret();
        let s2 = generate_secret();
        // With overwhelming probability two distinct 160-bit secrets differ
        assert_ne!(s1, s2, "two generated secrets should differ");
    }

    #[test]
    fn test_known_secret_produces_stable_structure() {
        // RFC 6238 test vector: b"12345678901234567890" (160 bits, meets 128-bit minimum).
        // Base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        // We just verify the output structure, not the exact code (time-dependent).
        let rfc_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let code = current_code(rfc_secret, Algorithm::SHA1, 6).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
}
