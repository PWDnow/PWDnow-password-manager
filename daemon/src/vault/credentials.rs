use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::crypto::{aes_gcm, xchacha20, blind_index};
use crate::error::VaultError;

const SCHEMA_VERSION: u32 = 1;

/// Lightweight metadata returned by `list` — no secret fields, no decryption.
#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialMeta {
    pub id: String,
    pub folder_id: Option<String>,
    pub schema_version: u32,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Deserialize)]
struct CredentialFields {
    service: Option<String>,
    url: Option<String>,
    username: Option<String>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Build the AAD for a credential ciphertext.
fn build_aad(vault_uuid: &str, cred_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(vault_uuid.len() + cred_id.len() + 4);
    aad.extend_from_slice(vault_uuid.as_bytes());
    aad.extend_from_slice(cred_id.as_bytes());
    aad
}

/// Generate a fresh per-credential DEK, wrap it with the VMK, and encrypt
/// `plaintext_blob` under the DEK. Shared by `add`/`update` so a future field
/// added to this sealing step only needs to change in one place.
fn seal_blob(
    vmk: &[u8; 32],
    vault_uuid: &str,
    cred_id: &str,
    plaintext_blob: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), VaultError> {
    let mut dek = [0u8; 32]; OsRng.fill_bytes(&mut dek);
    let (enc_dek, dek_nonce) = aes_gcm::encrypt(vmk, &dek, b"credential-dek-v1")?;
    let aad = build_aad(vault_uuid, cred_id);
    let (ciphertext, ct_nonce) = xchacha20::encrypt(&dek, plaintext_blob, &aad)?;
    dek.zeroize();
    Ok((enc_dek, dek_nonce.to_vec(), ciphertext, ct_nonce.to_vec(), aad))
}

/// Compute the (service, url, username) blind indices for a credential blob.
/// Shared by `add`/`update` so the set of indexed fields stays in sync.
fn compute_blind_indices(
    blind_index_key: &[u8; 64],
    plaintext_blob: &[u8],
) -> Result<(Option<String>, Option<String>, Option<String>), VaultError> {
    let fields: CredentialFields = serde_json::from_slice(plaintext_blob)
        .map_err(|_| VaultError::Crypto("invalid JSON blob".into()))?;

    let service_hash  = fields.service.and_then(|s| blind_index::compute(blind_index_key, &s).ok());
    let url_hash      = fields.url.and_then(|u| blind_index::compute(blind_index_key, &u).ok());
    let username_hash = fields.username.and_then(|u| blind_index::compute(blind_index_key, &u).ok());

    Ok((service_hash, url_hash, username_hash))
}

/// Add a new credential to the vault.
pub fn add(
    conn: &Connection,
    vmk: &[u8; 32],
    blind_index_key: &[u8; 64],
    vault_uuid: &str,
    folder_id: Option<Uuid>,
    plaintext_blob: &[u8],
) -> Result<Uuid, VaultError> {
    let id = Uuid::new_v4();
    let id_str = id.to_string();

    let (enc_dek, dek_nonce, ciphertext, ct_nonce, aad) =
        seal_blob(vmk, vault_uuid, &id_str, plaintext_blob)?;
    let (service_hash, url_hash, username_hash) =
        compute_blind_indices(blind_index_key, plaintext_blob)?;

    let ts = now();
    conn.execute(
        "INSERT INTO credentials (
            id, folder_id, schema_version, 
            encrypted_dek, dek_nonce, ciphertext, ct_nonce, ct_aad,
            service_hash, url_hash, username_hash,
            created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            id_str, folder_id.map(|u| u.to_string()), SCHEMA_VERSION,
            enc_dek, dek_nonce, ciphertext, ct_nonce, aad,
            service_hash, url_hash, username_hash,
            ts, ts
        ]
    )?;

    Ok(id)
}

/// Decrypt and return the plaintext blob for a single credential.
pub fn get(
    conn: &Connection,
    vmk: &[u8; 32],
    id: Uuid,
) -> Result<Vec<u8>, VaultError> {
    let row = conn.query_row(
        "SELECT encrypted_dek, dek_nonce, ciphertext, ct_nonce, ct_aad
         FROM credentials WHERE id=?1",
        params![id.to_string()],
        |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        },
    )?;

    let (enc_dek, dek_nonce, ct, ct_nonce, aad) = row;

    // 1. Unwrap DEK — #31-FIX: propagate error instead of panicking on short nonce
    let dek_nonce12: [u8; 12] = dek_nonce.get(..12)
        .ok_or_else(|| VaultError::Crypto("dek_nonce truncated".into()))?
        .try_into().map_err(|_| VaultError::Crypto("dek_nonce truncated".into()))?;
    let dek_vec = aes_gcm::decrypt(vmk, &enc_dek, &dek_nonce12, b"credential-dek-v1")?;
    let mut dek = [0u8; 32]; dek.copy_from_slice(&dek_vec);

    // 2. Decrypt ciphertext — #31-FIX: propagate error instead of panicking on short nonce
    let ct_nonce24: [u8; 24] = ct_nonce.get(..24)
        .ok_or_else(|| VaultError::Crypto("ct_nonce truncated".into()))?
        .try_into().map_err(|_| VaultError::Crypto("ct_nonce truncated".into()))?;
    let plain = xchacha20::decrypt(&dek, &ct, &ct_nonce24, &aad)?;
    dek.zeroize();

    Ok(plain)
}

/// Update an existing credential.
pub fn update(
    conn: &Connection,
    vmk: &[u8; 32],
    blind_index_key: &[u8; 64],
    vault_uuid: &str,
    id: Uuid,
    folder_id: Option<Uuid>,
    plaintext_blob: &[u8],
) -> Result<(), VaultError> {
    let id_str = id.to_string();
    let (enc_dek, dek_nonce, ciphertext, ct_nonce, aad) =
        seal_blob(vmk, vault_uuid, &id_str, plaintext_blob)?;
    let (service_hash, url_hash, username_hash) =
        compute_blind_indices(blind_index_key, plaintext_blob)?;

    conn.execute(
        "UPDATE credentials SET 
            folder_id=?1, encrypted_dek=?2, dek_nonce=?3, ciphertext=?4, ct_nonce=?5, ct_aad=?6,
            service_hash=?7, url_hash=?8, username_hash=?9, updated_at=?10
         WHERE id=?11",
        params![
            folder_id.map(|u| u.to_string()), enc_dek, dek_nonce, ciphertext, ct_nonce, aad,
            service_hash, url_hash, username_hash, now(), id_str
        ]
    )?;
    Ok(())
}

/// Delete a credential from the vault.
pub fn delete(conn: &Connection, id: Uuid) -> Result<(), VaultError> {
    conn.execute("DELETE FROM credentials WHERE id=?1", params![id.to_string()])?;
    Ok(())
}

/// List all credentials (metadata only).
pub fn list(
    conn: &Connection,
    folder_id: Option<Uuid>,
) -> Result<Vec<CredentialMeta>, VaultError> {
    let mut sql = "SELECT id, folder_id, schema_version, created_at, updated_at FROM credentials".to_string();
    let mut params_vec = vec![];
    if let Some(fid) = folder_id {
        sql.push_str(" WHERE folder_id = ?1");
        params_vec.push(fid.to_string());
    }

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(params_vec), |r| Ok(CredentialMeta {
        id:             r.get(0)?,
        folder_id:      r.get(1)?,
        schema_version: r.get::<_, u32>(2)?,
        created_at:     r.get(3)?,
        updated_at:     r.get(4)?,
    }))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn open() -> (NamedTempFile, Connection) {
        let f = NamedTempFile::new().unwrap();
        let c = crate::vault::db::open_vault(f.path(), &[0xAAu8; 32]).unwrap();
        (f, c)
    }

    const VMK: [u8; 32] = [0x11u8; 32];
    const BI_KEY: [u8; 64] = [0x22u8; 64];
    const VAULT_UUID: &str = "test-vault-uuid-v1";

    #[test]
    fn add_and_get_roundtrip() {
        let (_f, c) = open();
        let blob = b"{\"service\":\"github.com\",\"password\":\"s3cret\"}";
        let id = add(&c, &VMK, &BI_KEY, VAULT_UUID, None, blob).unwrap();
        let recovered = get(&c, &VMK, id).unwrap();
        assert_eq!(recovered, blob);
    }
}
