//! CNSA 2.0 algorithm policy enforcement.
//!
//! Reference: NSA CSI-CNSA-2.0 (Sept 2022), updated Apr 2024.

/// CNSA 2.0 algorithm suite identifiers.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CnsaSuite {
    /// Legacy — X25519, Ed25519, SHA-256, AES-256-GCM.
    Legacy       = 0x01,
    /// Hybrid PQ — X448+ML-KEM-1024, ML-DSA-87, SHA3-512, AES-256-GCM.
    HybridPq     = 0x02,
    /// CNSA strict — ML-KEM-1024, ML-DSA-87, SHA-384/512, AES-256-GCM.
    CnsaStrict   = 0x03,
}

/// Returns `true` if this binary enforces CNSA 2.0 strict mode at compile time.
pub const fn cnsa_strict() -> bool {
    cfg!(feature = "cnsa-strict")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cnsa_strict_flag() {
        #[cfg(feature = "cnsa-strict")]
        assert!(cnsa_strict());
        #[cfg(not(feature = "cnsa-strict"))]
        assert!(!cnsa_strict());
    }
}
