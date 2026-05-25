use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::VaultError;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// A row from the `fido2_credentials` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2CredRow {
    /// Internal UUID (primary key).
    pub id: String,
    /// Raw credential ID bytes returned by the authenticator.
    pub credential_id: Vec<u8>,
    /// COSE-encoded public key (ES256 for verification).
    pub public_key_cbor: Vec<u8>,
    /// Authenticator sign count (anti-clone detection).
    pub sign_count: u32,
    /// Optional AAGUID reported by the authenticator.
    pub aaguid: Option<String>,
    /// `true` when this credential is a resident key / passkey.
    pub is_passkey: bool,
    /// XChaCha20-Poly1305 ciphertext of the VMK (passkey Option B only).
    pub encrypted_vmk_copy: Option<Vec<u8>>,
    /// 24-byte nonce for `encrypted_vmk_copy`.
    pub vmk_copy_nonce: Option<Vec<u8>>,
    /// Human-readable label (e.g. "YubiKey 5C NFC").
    pub name: Option<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// Return all registered FIDO2 credentials ordered by `created_at`.
pub fn list(conn: &Connection) -> Result<Vec<Fido2CredRow>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT id, credential_id, public_key_cbor, sign_count, aaguid,
                is_passkey, encrypted_vmk_copy, vmk_copy_nonce, name,
                created_at, last_used_at
         FROM fido2_credentials ORDER BY created_at ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Fido2CredRow {
            id:                 r.get(0)?,
            credential_id:      r.get(1)?,
            public_key_cbor:    r.get(2)?,
            sign_count:         r.get::<_, i64>(3)? as u32,
            aaguid:             r.get(4)?,
            is_passkey:         r.get::<_, i64>(5)? != 0,
            encrypted_vmk_copy: r.get(6)?,
            vmk_copy_nonce:     r.get(7)?,
            name:               r.get(8)?,
            created_at:         r.get(9)?,
            last_used_at:       r.get(10)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Insert a new FIDO2 credential row (max 2 enforced by DB trigger).
/// Returns the generated UUID.
pub fn add(
    conn: &Connection,
    credential_id: &[u8],
    public_key_cbor: &[u8],
    aaguid: Option<&str>,
    is_passkey: bool,
    encrypted_vmk_copy: Option<&[u8]>,
    vmk_copy_nonce: Option<&[u8]>,
    name: Option<&str>,
) -> Result<Uuid, VaultError> {
    let id = Uuid::new_v4();
    conn.execute(
        "INSERT INTO fido2_credentials
             (id, credential_id, public_key_cbor, sign_count, aaguid,
              is_passkey, encrypted_vmk_copy, vmk_copy_nonce, name, created_at)
         VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            id.to_string(),
            credential_id,
            public_key_cbor,
            aaguid,
            is_passkey as i64,
            encrypted_vmk_copy,
            vmk_copy_nonce,
            name,
            now(),
        ],
    )?;
    Ok(id)
}

/// Look up a credential by its raw `credential_id` bytes (authenticator-assigned).
pub fn get_by_credential_id(
    conn: &Connection,
    credential_id: &[u8],
) -> Result<Fido2CredRow, VaultError> {
    conn.query_row(
        "SELECT id, credential_id, public_key_cbor, sign_count, aaguid,
                is_passkey, encrypted_vmk_copy, vmk_copy_nonce, name,
                created_at, last_used_at
         FROM fido2_credentials WHERE credential_id = ?1",
        params![credential_id],
        |r| Ok(Fido2CredRow {
            id:                 r.get(0)?,
            credential_id:      r.get(1)?,
            public_key_cbor:    r.get(2)?,
            sign_count:         r.get::<_, i64>(3)? as u32,
            aaguid:             r.get(4)?,
            is_passkey:         r.get::<_, i64>(5)? != 0,
            encrypted_vmk_copy: r.get(6)?,
            vmk_copy_nonce:     r.get(7)?,
            name:               r.get(8)?,
            created_at:         r.get(9)?,
            last_used_at:       r.get(10)?,
        }),
    )
    .map_err(Into::into)
}

/// Update the sign count and `last_used_at` after a successful assertion.
pub fn update_sign_count(
    conn: &Connection,
    id: &str,
    sign_count: u32,
) -> Result<(), VaultError> {
    let changed = conn.execute(
        "UPDATE fido2_credentials SET sign_count=?1, last_used_at=?2 WHERE id=?3",
        params![sign_count as i64, now(), id],
    )?;
    if changed == 0 {
        return Err(VaultError::Database(rusqlite::Error::QueryReturnedNoRows));
    }
    Ok(())
}

/// Delete a registered FIDO2 credential by its internal UUID.
pub fn remove(conn: &Connection, id: &str) -> Result<(), VaultError> {
    let changed = conn.execute(
        "DELETE FROM fido2_credentials WHERE id=?1",
        params![id],
    )?;
    if changed == 0 {
        return Err(VaultError::Database(rusqlite::Error::QueryReturnedNoRows));
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
    fn add_and_list() {
        let (_f, c) = open();
        let id = add(&c, &[0x01u8; 16], &[0x02u8; 64], None, false, None, None, Some("YubiKey")).unwrap();
        let rows = list(&c).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id.to_string());
        assert_eq!(rows[0].name.as_deref(), Some("YubiKey"));
        assert!(!rows[0].is_passkey);
        assert_eq!(rows[0].sign_count, 0);
    }

    #[test]
    fn get_by_credential_id_found() {
        let (_f, c) = open();
        let cred_id = [0xABu8; 20];
        add(&c, &cred_id, &[0x02u8; 64], Some("aaguid-1"), false, None, None, None).unwrap();
        let row = get_by_credential_id(&c, &cred_id).unwrap();
        assert_eq!(row.credential_id, cred_id);
        assert_eq!(row.aaguid.as_deref(), Some("aaguid-1"));
    }

    #[test]
    fn get_by_credential_id_not_found() {
        let (_f, c) = open();
        let result = get_by_credential_id(&c, &[0xFFu8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn update_sign_count_increments() {
        let (_f, c) = open();
        let id = add(&c, &[0x01u8; 16], &[0x02u8; 64], None, false, None, None, None).unwrap();
        update_sign_count(&c, &id.to_string(), 42).unwrap();
        let row = get_by_credential_id(&c, &[0x01u8; 16]).unwrap();
        assert_eq!(row.sign_count, 42);
        assert!(row.last_used_at.is_some());
    }

    #[test]
    fn remove_credential() {
        let (_f, c) = open();
        let id = add(&c, &[0x01u8; 16], &[0x02u8; 64], None, false, None, None, None).unwrap();
        remove(&c, &id.to_string()).unwrap();
        assert_eq!(list(&c).unwrap().len(), 0);
    }

    #[test]
    fn remove_nonexistent_errors() {
        let (_f, c) = open();
        let result = remove(&c, "nonexistent-id");
        assert!(result.is_err());
    }

    #[test]
    fn db_trigger_enforces_max_two_keys() {
        let (_f, c) = open();
        add(&c, &[0x01u8; 16], &[0x02u8; 64], None, false, None, None, Some("Key1")).unwrap();
        add(&c, &[0x03u8; 16], &[0x04u8; 64], None, false, None, None, Some("Key2")).unwrap();
        let result = add(&c, &[0x05u8; 16], &[0x06u8; 64], None, false, None, None, Some("Key3"));
        assert!(result.is_err(), "third key must be rejected by DB trigger");
    }

    #[test]
    fn passkey_stores_vmk_copy() {
        let (_f, c) = open();
        let vmk_copy = vec![0xDEu8; 48]; // 32-byte VMK + 16-byte tag
        let nonce = vec![0xBEu8; 24];
        let id = add(&c, &[0x01u8; 16], &[0x02u8; 64], None, true,
                     Some(&vmk_copy), Some(&nonce), Some("Passkey")).unwrap();
        let row = get_by_credential_id(&c, &[0x01u8; 16]).unwrap();
        assert!(row.is_passkey);
        assert_eq!(row.encrypted_vmk_copy.unwrap(), vmk_copy);
        assert_eq!(row.vmk_copy_nonce.unwrap(), nonce);
        let _ = id;
    }
}
