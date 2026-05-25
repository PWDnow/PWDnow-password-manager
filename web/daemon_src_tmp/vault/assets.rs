use rusqlite::{Connection, params};

use crate::crypto::{aes_gcm, xchacha20};
use crate::error::VaultError;

const ASSET_HOLDER_ID: &str = "singleton";
const AAD: &[u8] = b"asset-holder-v1";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Return the decrypted asset holder blob.
pub fn get(conn: &Connection, vmk: &[u8; 32]) -> Result<Option<Vec<u8>>, VaultError> {
    let result = conn.query_row(
        "SELECT ciphertext, nonce FROM asset_holder WHERE id=?1",
        params![ASSET_HOLDER_ID],
        |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
    );

    match result {
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
        Ok((ciphertext, nonce_raw)) => {
            let blob = match nonce_raw.len() {
                12 => {
                    let nonce: [u8; 12] = nonce_raw.try_into().unwrap();
                    aes_gcm::decrypt(vmk, &ciphertext, &nonce, AAD)?
                }
                24 => {
                    let nonce: [u8; 24] = nonce_raw.try_into().unwrap();
                    xchacha20::decrypt(vmk, &ciphertext, &nonce, AAD)?
                }
                _ => return Err(VaultError::Crypto("invalid asset nonce length".into())),
            };
            Ok(Some(blob))
        }
    }
}

/// Encrypt `blob` and upsert the asset holder row.
pub fn update(conn: &Connection, vmk: &[u8; 32], blob: &[u8]) -> Result<(), VaultError> {
    let (ciphertext, nonce) = aes_gcm::encrypt(vmk, blob, AAD)?;
    conn.execute(
        "INSERT INTO asset_holder (id, ciphertext, nonce, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(id) DO UPDATE SET ciphertext=excluded.ciphertext,
             nonce=excluded.nonce, updated_at=excluded.updated_at",
        params![ASSET_HOLDER_ID, ciphertext, nonce.as_slice(), now()],
    )?;
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

    const VMK: [u8; 32] = [0x22u8; 32];

    #[test]
    fn get_returns_none_when_not_set() {
        let (_f, c) = open();
        assert!(get(&c, &VMK).unwrap().is_none());
    }

    #[test]
    fn update_and_get_roundtrip() {
        let (_f, c) = open();
        let blob = b"{\"emails\":[\"a@b.com\"],\"phoneNumbers\":[],\"u2fKeys\":[]}";
        update(&c, &VMK, blob).unwrap();
        let recovered = get(&c, &VMK).unwrap().unwrap();
        assert_eq!(recovered, blob);
    }
}
