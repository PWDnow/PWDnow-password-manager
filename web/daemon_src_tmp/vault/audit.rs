use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use crate::error::VaultError;

/// A serialisable audit log entry returned by `GetAuditLog`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    /// Nanoseconds since UNIX epoch (C.6: promoted from second-precision).
    pub ts: i64,
    pub action: String,
    pub resource: Option<String>,
}

/// Well-known audit action strings (D-11 / C.5).
pub const ACTION_UNLOCK_FAILED:        &str = "UNLOCK_FAILED";

/// Nanosecond-precision monotonic timestamp (C.6).
/// Stores nanoseconds since UNIX epoch as i64 — fits until year 2262.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

fn get_mac_key(vmk: &[u8; 32]) -> [u8; 32] {
    use sha3::Sha3_512;
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha3_512>::new(None, vmk);
    let mut key = [0u8; 32];
    hk.expand(b"vault-audit-mac-key-v1", &mut key).unwrap();
    key
}

/// Compute the audit row hash.
///
/// Default (non-cnsa-strict): `BLAKE3-MAC(ts_be8 || action || resource || prev_hash)` — 32 bytes.
/// CNSA strict: `HMAC-SHA384(0x02 || ts_be8 || action || resource || prev_hash)` — 48 bytes.
/// The leading `0x02` suite-ID byte makes chains self-identifying across migrations.
fn compute_row_hash(mac_key: &[u8; 32], ts: i64, action: &str, resource: Option<&str>, prev_hash: &[u8]) -> Vec<u8> {
    #[cfg(feature = "cnsa-strict")]
    {
        use hmac::{Hmac, Mac};
        use sha2::Sha384;
        let mut mac = Hmac::<Sha384>::new_from_slice(mac_key).unwrap();
        mac.update(&[0x02u8]); // CNSA suite ID
        mac.update(&ts.to_be_bytes());
        mac.update(action.as_bytes());
        if let Some(r) = resource { mac.update(r.as_bytes()); }
        mac.update(prev_hash);
        mac.finalize().into_bytes().to_vec()
    }
    #[cfg(not(feature = "cnsa-strict"))]
    {
        let mut mac = blake3::Hasher::new_keyed(mac_key);
        mac.update(&ts.to_be_bytes());
        mac.update(action.as_bytes());
        if let Some(r) = resource { mac.update(r.as_bytes()); }
        mac.update(prev_hash);
        mac.finalize().as_bytes().to_vec()
    }
}

/// Zero-value hash for an empty chain (matches hash-function output length).
fn zero_prev_hash() -> Vec<u8> {
    #[cfg(feature = "cnsa-strict")]
    { vec![0u8; 48] }
    #[cfg(not(feature = "cnsa-strict"))]
    { vec![0u8; 32] }
}

/// Fetch the hash of the last audit row, or zero bytes if the log is empty.
fn last_row_hash(conn: &Connection) -> Result<Vec<u8>, VaultError> {
    match conn.query_row(
        "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1",
        [],
        |r| r.get::<_, Vec<u8>>(0),
    ) {
        Ok(h) => Ok(h),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(zero_prev_hash()),
        Err(e) => Err(e.into()),
    }
}

/// Append one entry to the audit log.
///
/// Row hash algorithm is selected at compile time by the `cnsa-strict` feature:
/// - Default: `BLAKE3(ts_be8 || action || resource || prev_hash)` (32 bytes)
/// - CNSA strict: `SHA-384(0x02 || ts_be8 || action || resource || prev_hash)` (48 bytes)
pub fn log(conn: &Connection, vmk: &[u8; 32], action: &str, resource: Option<&str>) -> Result<(), VaultError> {
    let mac_key = get_mac_key(vmk);
    let ts = now();
    let prev_hash = last_row_hash(conn)?;
    let row_hash = compute_row_hash(&mac_key, ts, action, resource, &prev_hash);

    conn.execute(
        "INSERT INTO audit_log (ts, action, resource, prev_hash, row_hash)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![ts, action, resource, prev_hash.as_slice(), row_hash.as_slice()],
    )?;
    Ok(())
}

/// Return the most recent `limit` audit entries, newest first.
/// `limit` is capped at 1000 to prevent oversized responses.
pub fn list(conn: &Connection, limit: u32) -> Result<Vec<AuditEntry>, VaultError> {
    let cap = limit.min(1000);
    let mut stmt = conn.prepare(
        "SELECT id, ts, action, resource FROM audit_log ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![cap], |r| {
        Ok(AuditEntry {
            id:       r.get(0)?,
            ts:       r.get(1)?,
            action:   r.get(2)?,
            resource: r.get(3)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Verify the integrity chain of the entire audit log.
/// Returns `Ok(())` if all hashes are consistent, `Err` if any row is tampered.
pub fn verify_chain(conn: &Connection, vmk: &[u8; 32]) -> Result<(), VaultError> {
    let mac_key = get_mac_key(vmk);
    let mut stmt = conn.prepare(
        "SELECT id, ts, action, resource, prev_hash, row_hash FROM audit_log ORDER BY id ASC",
    )?;
    let mut expected_prev = zero_prev_hash();
    let mut last_id: Option<i64> = None;

    let rows: Vec<_> = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Vec<u8>>(4)?,
            r.get::<_, Vec<u8>>(5)?,
        ))
    })?
    .collect::<Result<_, _>>()?;

    for (id, ts, action, resource, stored_prev, stored_hash) in rows {
        // #26-FIX: assert strict ID monotonicity to detect row deletion or injection.
        if let Some(prev_id) = last_id {
            if id != prev_id + 1 {
                return Err(VaultError::Crypto(
                    "audit log chain broken: id gap detected".into(),
                ));
            }
        }
        last_id = Some(id);

        if stored_prev.as_slice() != expected_prev.as_slice() {
            return Err(VaultError::Crypto(
                "audit log chain broken: prev_hash mismatch".into(),
            ));
        }
        let expected_hash = compute_row_hash(&mac_key, ts, &action, resource.as_deref(), &expected_prev);
        if stored_hash.as_slice() != expected_hash.as_slice() {
            return Err(VaultError::Crypto(
                "audit log chain broken: row_hash mismatch".into(),
            ));
        }
        expected_prev = expected_hash;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use crate::vault::db::open_vault;

    fn open() -> (NamedTempFile, Connection) {
        let f = NamedTempFile::new().unwrap();
        let c = open_vault(f.path(), &[0xAAu8; 32]).unwrap();
        (f, c)
    }

    #[test]
    fn log_single_entry() {
        let (_f, c) = open();
        let vmk = [0u8; 32];
        log(&c, &vmk, "LOGIN_OK", Some("user-1")).unwrap();
        let n: i64 = c.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn chain_is_valid_after_multiple_entries() {
        let (_f, c) = open();
        let vmk = [0u8; 32];
        log(&c, &vmk, "LOGIN_OK", Some("user-1")).unwrap();
        log(&c, &vmk, "CRED_ADD", Some("cred-abc")).unwrap();
        log(&c, &vmk, "CRED_DELETE", Some("cred-abc")).unwrap();
        verify_chain(&c, &vmk).unwrap();
    }

    #[test]
    fn verify_empty_log_succeeds() {
        let (_f, c) = open();
        let vmk = [0u8; 32];
        verify_chain(&c, &vmk).unwrap();
    }

    #[test]
    fn tampered_row_hash_breaks_chain() {
        let (_f, c) = open();
        let vmk = [0u8; 32];
        log(&c, &vmk, "LOGIN_OK", Some("user-1")).unwrap();
        log(&c, &vmk, "CRED_ADD", Some("cred-xyz")).unwrap();
        // Corrupt the row_hash of the first row — length matches the active hash function.
        #[cfg(not(feature = "cnsa-strict"))]
        c.execute(
            "UPDATE audit_log SET row_hash=X'DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF' WHERE id=1",
            [],
        ).unwrap();
        // SHA-384 produces 48 bytes (96 hex chars).
        #[cfg(feature = "cnsa-strict")]
        c.execute(
            "UPDATE audit_log SET row_hash=X'DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF' WHERE id=1",
            [],
        ).unwrap();
        assert!(verify_chain(&c, &vmk).is_err(), "corrupted chain must fail verification");
    }

    #[test]
    fn deleted_row_breaks_chain() {
        let (_f, c) = open();
        let vmk = [0u8; 32];
        log(&c, &vmk, "LOGIN_OK", None).unwrap();
        log(&c, &vmk, "CRED_ADD", Some("x")).unwrap();
        log(&c, &vmk, "CRED_ADD", Some("y")).unwrap();
        // Delete the middle row
        c.execute("DELETE FROM audit_log WHERE id=2", []).unwrap();
        assert!(verify_chain(&c, &vmk).is_err(), "deleted row must break chain");
    }

    #[test]
    fn hashes_differ_for_different_actions() {
        let (_f, c) = open();
        let vmk = [0u8; 32];
        log(&c, &vmk, "LOGIN_OK", None).unwrap();
        log(&c, &vmk, "LOGIN_FAIL", None).unwrap();
        let hashes: Vec<Vec<u8>> = {
            let mut stmt = c.prepare("SELECT row_hash FROM audit_log ORDER BY id ASC").unwrap();
            stmt.query_map([], |r| r.get(0)).unwrap()
                .collect::<Result<_, _>>().unwrap()
        };
        assert_ne!(hashes[0], hashes[1]);
    }
}

