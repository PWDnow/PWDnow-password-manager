use rusqlite::{Connection, params};
use uuid::Uuid;
use crate::error::VaultError;

/// A registered PQC credential.
pub struct PqcCredRow {
    pub id: String,
    pub credential_id: Vec<u8>,
    pub verifying_key: Vec<u8>,
    pub encapsulation_key: Vec<u8>,
    pub name: Option<String>,
}

/// Register a new PQC credential in the vault.
pub fn add(
    conn: &Connection,
    credential_id: &[u8],
    verifying_key: &[u8],
    encapsulation_key: &[u8],
    enc_seed: &[u8],
    nonce: &[u8],
    name: Option<&str>,
) -> Result<Uuid, VaultError> {
    let id = Uuid::new_v4();
    let id_str = id.to_string();
    conn.execute(
        "INSERT INTO pqc_credentials (
            id, credential_id, verifying_key, encapsulation_key, 
            enc_seed, nonce, name
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id_str, credential_id, verifying_key, encapsulation_key,
            enc_seed, nonce, name
        ],
    )?;
    Ok(id)
}

/// List all PQC credentials.
pub fn list(conn: &Connection) -> Result<Vec<PqcCredRow>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT id, credential_id, verifying_key, encapsulation_key, name FROM pqc_credentials"
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(PqcCredRow {
            id:                r.get(0)?,
            credential_id:     r.get(1)?,
            verifying_key:     r.get(2)?,
            encapsulation_key: r.get(3)?,
            name:              r.get(4)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Delete a PQC credential.
pub fn delete(conn: &Connection, id: &str) -> Result<(), VaultError> {
    conn.execute("DELETE FROM pqc_credentials WHERE id = ?1", params![id])?;
    Ok(())
}
