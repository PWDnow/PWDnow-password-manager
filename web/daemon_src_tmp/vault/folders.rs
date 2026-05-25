use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{aes_gcm, xchacha20};
use crate::error::VaultError;


#[derive(Debug, Serialize, Deserialize)]
pub struct FolderRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub icon_svg: Option<String>,
    pub sort_order: i64,
    pub schema_version: u32,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize)]
struct FolderMetadata {
    name: String,
    description: Option<String>,
    icon_svg: Option<String>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

const FOLDER_SCHEMA_VERSION: u32 = 1;

// ── Crypto helpers ────────────────────────────────────────────────────────────

fn build_aad(vault_uuid: &str, id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(vault_uuid.len() + id.len() + 4);
    aad.extend_from_slice(vault_uuid.as_bytes());
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(&FOLDER_SCHEMA_VERSION.to_be_bytes());
    aad
}

fn encrypt_folder(vmk: &[u8; 32], vault_uuid: &str, id: &str, meta: &FolderMetadata) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    let json = serde_json::to_vec(meta)
        .map_err(|e| VaultError::Crypto(format!("folder serialize: {e}")))?;
    let aad = build_aad(vault_uuid, id);
    let (ct, nonce) = aes_gcm::encrypt(vmk, &json, &aad)?;
    Ok((ct, nonce.to_vec()))
}

fn decrypt_folder(vmk: &[u8; 32], vault_uuid: &str, id: &str, ciphertext: &[u8], nonce_vec: &[u8]) -> Result<FolderMetadata, VaultError> {
    let aad = build_aad(vault_uuid, id);
    let json = match nonce_vec.len() {
        12 => {
            let nonce: [u8; 12] = nonce_vec.try_into().unwrap();
            aes_gcm::decrypt(vmk, ciphertext, &nonce, &aad)?
        }
        24 => {
            let nonce: [u8; 24] = nonce_vec.try_into().unwrap();
            xchacha20::decrypt(vmk, ciphertext, &nonce, &aad)?
        }
        _ => return Err(VaultError::Crypto("invalid folder nonce length".into())),
    };
    serde_json::from_slice(&json)
        .map_err(|e| VaultError::Crypto(format!("folder deserialize: {e}")))
}

// ── CRUD ──────────────────────────────────────────────────────────────────────

pub fn list(conn: &Connection, vmk: &[u8; 32], vault_uuid: &str) -> Result<Vec<FolderRow>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT id, ciphertext, nonce, sort_order, created_at, updated_at
         FROM folders ORDER BY sort_order ASC",
    )?;
    
    let mut rows = stmt.query([])?;
    let mut result = Vec::new();
    
    while let Some(r) = rows.next()? {
        let id: String = r.get(0)?;
        let ct_opt: Option<Vec<u8>> = r.get(1)?;
        let nonce_opt: Option<Vec<u8>> = r.get(2)?;
        let sort_order: i64 = r.get(3)?;
        let created_at: i64 = r.get(4)?;
        let updated_at: i64 = r.get(5)?;

        if let (Some(ct), Some(nonce)) = (ct_opt, nonce_opt) {
            match decrypt_folder(vmk, vault_uuid, &id, &ct, &nonce) {
                Ok(meta) => {
                    result.push(FolderRow {
                        id,
                        name:        meta.name,
                        description: meta.description,
                        icon_svg:    meta.icon_svg,
                        sort_order,
                        schema_version: FOLDER_SCHEMA_VERSION,
                        created_at,
                        updated_at,
                    });
                }
                Err(e) => {
                    tracing::trace!(%e, "failed to decrypt folder; skipping"); // #21-FIX: trace-only (no id in output)
                }
            }
        } else {
            result.push(FolderRow {
                id,
                name: "Pending Migration".into(),
                description: Some("Data migration in progress".into()),
                icon_svg: None,
                sort_order,
                schema_version: 0,
                created_at,
                updated_at,
            });
        }
    }
    Ok(result)
}

pub fn add(
    conn: &Connection,
    vmk: &[u8; 32],
    vault_uuid: &str,
    name: &str,
    description: Option<&str>,
    icon_svg: Option<&str>,
) -> Result<Uuid, VaultError> {
    let id = Uuid::new_v4();
    let ts = now();
    
    let meta = FolderMetadata {
        name: name.to_string(),
        description: description.map(|s| s.to_string()),
        icon_svg: icon_svg.map(|s| s.to_string()),
    };
    let (ct, nonce) = encrypt_folder(vmk, vault_uuid, &id.to_string(), &meta)?;

    let next_order: i64 = conn.query_row(
        "SELECT COALESCE(MAX(sort_order) + 1, 0) FROM folders",
        [],
        |r| r.get(0),
    )?;
    
    conn.execute(
        "INSERT INTO folders (id, ciphertext, nonce, sort_order, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![id.to_string(), ct, nonce, next_order, ts],
    )?;
    Ok(id)
}

pub fn update(
    conn: &Connection,
    vmk: &[u8; 32],
    vault_uuid: &str,
    id: Uuid,
    name: &str,
    description: Option<&str>,
    icon_svg: Option<&str>,
) -> Result<(), VaultError> {
    let meta = FolderMetadata {
        name: name.to_string(),
        description: description.map(|s| s.to_string()),
        icon_svg: icon_svg.map(|s| s.to_string()),
    };
    let (ct, nonce) = encrypt_folder(vmk, vault_uuid, &id.to_string(), &meta)?;

    let changed = conn.execute(
        "UPDATE folders SET ciphertext=?1, nonce=?2, updated_at=?3 WHERE id=?4",
        params![ct, nonce, now(), id.to_string()],
    )?;
    if changed == 0 {
        return Err(VaultError::Database(rusqlite::Error::QueryReturnedNoRows));
    }
    Ok(())
}

pub fn delete(
    conn: &Connection,
    id: Uuid,
    move_credentials_to: Option<Uuid>,
) -> Result<(), VaultError> {
    let id_str = id.to_string();
    match move_credentials_to {
        Some(target) => {
            conn.execute(
                "UPDATE credentials SET folder_id=?1 WHERE folder_id=?2",
                params![target.to_string(), id_str],
            )?;
        }
        None => {
            conn.execute("DELETE FROM credentials WHERE folder_id=?1", params![id_str])?;
        }
    }
    let changed = conn.execute("DELETE FROM folders WHERE id=?1", params![id_str])?;
    if changed == 0 {
        return Err(VaultError::Database(rusqlite::Error::QueryReturnedNoRows));
    }
    Ok(())
}

pub fn reorder(conn: &Connection, ordered_ids: &[Uuid]) -> Result<(), VaultError> {
    let ts = now();
    conn.execute("BEGIN IMMEDIATE", [])?;
    let result: Result<(), VaultError> = (|| {
        for (i, id) in ordered_ids.iter().enumerate() {
            conn.execute(
                "UPDATE folders SET sort_order=?1, updated_at=?2 WHERE id=?3",
                params![i as i64, ts, id.to_string()],
            )?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => { conn.execute("COMMIT", [])?; Ok(()) }
        Err(e) => { let _ = conn.execute("ROLLBACK", []); Err(e) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use crate::vault::db::{open_vault};

    fn open() -> (NamedTempFile, Connection) {
        let f = NamedTempFile::new().unwrap();
        let c = open_vault(f.path(), &[0xAAu8; 32]).unwrap();
        (f, c)
    }

    const VMK: [u8; 32] = [0x42u8; 32];

    #[test]
    fn add_and_list() {
        let (_f, c) = open();
        const VUUID: &str = "test-vault-uuid";
        let id = add(&c, &VMK, VUUID, "Personal", Some("my stuff"), None).unwrap();
        let folders = list(&c, &VMK, VUUID).unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].id, id.to_string());
        assert_eq!(folders[0].name, "Personal");
    }
}
