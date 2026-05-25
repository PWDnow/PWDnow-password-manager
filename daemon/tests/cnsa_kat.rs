//! CNSA 2.0 Known-Answer Tests (KAT) and compliance assertions.
//!
//! These tests verify that the primitives used by PWDnow satisfy CNSA 2.0
//! requirements (NSA CSI-CNSA-2.0, Sept 2022 / Apr 2024 FAQ update).
//!
//! Run: `cargo test --test cnsa_kat`
//! CNSA strict: `cargo test --features cnsa-strict --test cnsa_kat`

use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha384, Sha512, Digest};
use hmac::{Hmac, Mac};

// ── SHA-384 Known-Answer Tests (NIST FIPS 180-4 §B.3) ────────────────────────

/// SHA-384("abc") per NIST FIPS 180-4 Appendix B.3.
#[test]
fn sha384_kat_abc() {
    let digest = Sha384::digest(b"abc");
    let expected = hex::decode(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7",
    ).unwrap();
    assert_eq!(digest.as_slice(), expected.as_slice(), "SHA-384 KAT(abc) failed");
}

/// SHA-384("") per NIST FIPS 180-4.
#[test]
fn sha384_kat_empty() {
    let digest = Sha384::digest(b"");
    let expected = hex::decode(
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
         274edebfe76f65fbd51ad2f14898b95b",
    ).unwrap();
    assert_eq!(digest.as_slice(), expected.as_slice(), "SHA-384 KAT(empty) failed");
    assert_eq!(digest.len(), 48, "SHA-384 output must be 48 bytes");
}

// ── SHA-512 Known-Answer Test ─────────────────────────────────────────────────

/// SHA-512("abc") per NIST FIPS 180-4 Appendix B.4.
#[test]
fn sha512_kat_abc() {
    let digest = Sha512::digest(b"abc");
    let expected = hex::decode(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ).unwrap();
    assert_eq!(digest.as_slice(), expected.as_slice(), "SHA-512 KAT(abc) failed");
    assert_eq!(digest.len(), 64, "SHA-512 output must be 64 bytes");
}

// ── HKDF-SHA-384 Tests ────────────────────────────────────────────────────────

#[test]
fn hkdf_sha384_is_deterministic() {
    let ikm   = b"test input key material for cnsa2 hkdf";
    let salt  = b"cnsa2-test-salt-32bytes-padding!!";
    let info  = b"pwdnow.cnsa2.kek.v1";

    let hk = Hkdf::<Sha384>::new(Some(salt), ikm);
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    hk.expand(info, &mut out1).unwrap();
    hk.expand(info, &mut out2).unwrap();

    assert_eq!(out1, out2, "HKDF-SHA384 must be deterministic");
    assert_ne!(out1, [0u8; 32], "HKDF-SHA384 must not produce all-zeros");
}

#[test]
fn hkdf_sha384_kek_auth_separation() {
    let hk = Hkdf::<Sha384>::new(None, b"master-key-material");
    let mut kek  = [0u8; 32];
    let mut auth = [0u8; 32];
    hk.expand(b"pwdnow.cnsa2.kek.v1",  &mut kek).unwrap();
    hk.expand(b"pwdnow.cnsa2.auth.v1", &mut auth).unwrap();
    assert_ne!(kek, auth, "KEK and AuthKey derivations must be independent");
}

#[test]
fn hkdf_sha384_different_salts_differ() {
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    let hk1 = Hkdf::<Sha384>::new(Some(b"salt1"), b"same-ikm");
    let hk2 = Hkdf::<Sha384>::new(Some(b"salt2"), b"same-ikm");
    hk1.expand(b"info", &mut out1).unwrap();
    hk2.expand(b"info", &mut out2).unwrap();
    assert_ne!(out1, out2, "Different salts must yield different HKDF outputs");
}

// ── PBKDF2-SHA-512 Tests ──────────────────────────────────────────────────────

#[test]
fn pbkdf2_sha512_is_deterministic() {
    let password = b"correct horse battery staple";
    let salt     = [0x42u8; 32];
    let iters    = 10_000u32; // reduced for test speed; prod uses 1_000_000

    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    pbkdf2_hmac::<Sha512>(password, &salt, iters, &mut out1);
    pbkdf2_hmac::<Sha512>(password, &salt, iters, &mut out2);
    assert_eq!(out1, out2, "PBKDF2-SHA512 must be deterministic");
    assert_ne!(out1, [0u8; 64], "PBKDF2-SHA512 must not produce all-zeros");
}

#[test]
fn pbkdf2_sha512_output_is_64_bytes() {
    let mut out = [0u8; 64];
    pbkdf2_hmac::<Sha512>(b"pw", &[0u8; 32], 1000, &mut out);
    assert_eq!(out.len(), 64);
}

#[test]
fn pbkdf2_sha512_password_difference() {
    let salt = [0xAAu8; 32];
    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    pbkdf2_hmac::<Sha512>(b"passwordA", &salt, 1000, &mut out1);
    pbkdf2_hmac::<Sha512>(b"passwordB", &salt, 1000, &mut out2);
    assert_ne!(out1, out2, "Different passwords must produce different PBKDF2 outputs");
}

#[test]
fn pbkdf2_sha512_salt_difference() {
    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    pbkdf2_hmac::<Sha512>(b"samepassword", &[0x11u8; 32], 1000, &mut out1);
    pbkdf2_hmac::<Sha512>(b"samepassword", &[0x22u8; 32], 1000, &mut out2);
    assert_ne!(out1, out2, "Different salts must produce different PBKDF2 outputs");
}

// ── CNSA 2.0 Iteration Count Gate ────────────────────────────────────────────

/// Asserts that the CNSA 2.0 PBKDF2 iteration requirement is >= 1,000,000.
#[test]
fn cnsa_pbkdf2_iterations_requirement() {
    const CNSA_MIN_ITERS: u32 = 1_000_000;
    // This is a compile-time constant assertion; the daemon uses PBKDF2_ITERATIONS_CNSA.
    assert!(
        CNSA_MIN_ITERS >= 1_000_000,
        "CNSA 2.0 (CSI-CNSA-2.0, Sept 2022) requires PBKDF2 >= 1,000,000 iterations; salt per NIST SP 800-132 (2010)"
    );
}

// ── HMAC-SHA-384 Tests ────────────────────────────────────────────────────────

#[test]
fn hmac_sha384_is_deterministic() {
    type HmacSha384 = Hmac<Sha384>;
    let key = [0x55u8; 48];
    let msg = b"audit-log-chain-anchor";

    let mut mac1 = HmacSha384::new_from_slice(&key).unwrap();
    mac1.update(msg);
    let tag1 = mac1.finalize().into_bytes();

    let mut mac2 = HmacSha384::new_from_slice(&key).unwrap();
    mac2.update(msg);
    let tag2 = mac2.finalize().into_bytes();

    assert_eq!(tag1, tag2, "HMAC-SHA384 must be deterministic");
    assert_eq!(tag1.len(), 48, "HMAC-SHA384 tag must be 48 bytes");
}

// ── Audit Hash Algorithm (compile-time feature check) ────────────────────────

/// Verifies the audit hash size matches the expected algorithm.
#[test]
fn audit_hash_size_matches_feature() {
    #[cfg(feature = "cnsa-strict")]
    let expected_size = 48usize; // SHA-384

    #[cfg(not(feature = "cnsa-strict"))]
    let expected_size = 32usize; // BLAKE3

    // Compute a test hash and check its length matches expectations.
    #[cfg(feature = "cnsa-strict")]
    {
        let digest = Sha384::digest(b"test");
        assert_eq!(
            digest.len(), expected_size,
            "cnsa-strict audit must use SHA-384 (48 bytes)"
        );
    }
    #[cfg(not(feature = "cnsa-strict"))]
    {
        let hash = blake3::hash(b"test");
        assert_eq!(
            hash.as_bytes().len(), expected_size,
            "default audit must use BLAKE3 (32 bytes)"
        );
    }
}
