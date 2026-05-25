use rusqlite::{Connection, OpenFlags, params};
use std::path::Path;
use crate::error::VaultError;

pub const CURRENT_SCHEMA_VERSION: u32 = 4;

/// Open or create an SQLCipher-encrypted vault file.
pub fn open_vault(path: &Path, sqlcipher_key: &[u8; 32]) -> Result<Connection, VaultError> {
    // C-09: Ensure file has 0o600 permissions even in dev.
    if !path.exists() {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true).create(true).mode(0o600).open(path)
            .map_err(VaultError::Io)?;
    } else {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
    ).map_err(VaultError::Database)?;

    // #9: SQLCipher requires the x'<hex>' format to pass raw bytes without PBKDF2.
    // sqlcipher_key is always a [u8; 32] derived from HKDF — never user-controlled.
    // Use debug_assert to catch future callers that accidentally pass attacker data.
    debug_assert_eq!(sqlcipher_key.len(), 32, "sqlcipher_key must be exactly 32 bytes");
    let key_hex = format!("x'{}'", hex::encode(sqlcipher_key));
    conn.pragma_update(None, "key", &key_hex).map_err(VaultError::Database)?;

    // M-04: SQLCipher hardening defaults.
    conn.pragma_update(None, "cipher_compatibility", 4).map_err(VaultError::Database)?;
    // cipher_integrity_check returns "ok" if all pages pass, or per-page error messages.
    // On a brand-new (0-page) database SQLCipher may return zero rows — treat that as ok.
    let integrity_result = conn.pragma_query_value::<String, _>(None, "cipher_integrity_check", |r| r.get(0));
    match integrity_result {
        Ok(ref s) if s != "ok" => {
            return Err(VaultError::Database(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
                Some(format!("cipher_integrity_check: {s}"))
            )));
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => { /* fresh empty DB — no pages to check */ }
        Err(e) => return Err(VaultError::Database(e)),
        Ok(_) => { /* "ok" */ }
    }

    apply_migrations(&conn)?;

    // M-53 fix: set application_id for file format identification.
    // 0x5057444E = "PWDN"
    conn.pragma_update(None, "application_id", 0x5057444E).map_err(VaultError::Database)?;

    conn.pragma_update(None, "foreign_keys", "ON").map_err(VaultError::Database)?;
    conn.pragma_update(None, "journal_mode", "WAL").map_err(VaultError::Database)?;
    // FULL ensures every committed write is fsync'd to disk before the call
    // returns. Combined with WAL this gives durability on power loss (NORMAL
    // can lose the last committed transaction on a crash or power cut).
    conn.pragma_update(None, "synchronous", "FULL").map_err(VaultError::Database)?;

    Ok(conn)
}

/// Change the SQLCipher encryption key of an open database.
pub fn rekey_vault(conn: &Connection, _old_key: &[u8; 32], new_key: &[u8; 32]) -> Result<(), VaultError> {
    // M-03: Use x'...' for rekey too.
    let key_hex = format!("x'{}'", hex::encode(new_key));
    conn.pragma_update(None, "rekey", key_hex).map_err(VaultError::Database)?;
    Ok(())
}

fn schema_version(conn: &Connection) -> Result<u32, VaultError> {
    let result: rusqlite::Result<u32> = conn.query_row(
        "SELECT value FROM vault_meta WHERE key = 'schema_version'",
        [],
        |r| r.get(0),
    );
    match result {
        Ok(v) => Ok(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        Err(e) => { let msg = e.to_string(); if msg.contains("no such table: vault_meta") { Ok(0) } else { Err(e.into()) } }
    }
}

fn apply_migrations(conn: &Connection) -> Result<(), VaultError> {
    let version = schema_version(conn)?;
    if version >= CURRENT_SCHEMA_VERSION {
        return Ok(());
    }

    // Wrap the entire migration chain in a single atomic transaction so a
    // crash between two version steps rolls back to the previous clean state
    // rather than leaving a partial schema that the next open cannot repair.
    conn.execute_batch("BEGIN IMMEDIATE").map_err(VaultError::Database)?;
    let result = (|| {
        if version < 1 { migrate_v0_to_v1(conn)?; }
        if version < 2 { migrate_v1_to_v2(conn)?; }
        if version < 3 { migrate_v2_to_v3(conn)?; }
        if version < 4 { migrate_v3_to_v4(conn)?; }
        Ok::<(), VaultError>(())
    })();
    match result {
        Ok(()) => { conn.execute_batch("COMMIT").map_err(VaultError::Database)?; }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    }
    Ok(())
}

fn migrate_v0_to_v1(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(include_str!("../../migrations/v1_initial.sql"))?;
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', ?1)",
        params![1],
    )?;
    Ok(())
}

fn migrate_v1_to_v2(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(include_str!("../../migrations/v2_defense_in_depth.sql"))?;
    conn.execute(
        "UPDATE vault_meta SET value = ?1 WHERE key = 'schema_version'",
        params![2],
    )?;
    Ok(())
}

fn migrate_v2_to_v3(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(include_str!("../../migrations/v3_pqc_auth.sql"))?;
    conn.execute(
        "UPDATE vault_meta SET value = ?1 WHERE key = 'schema_version'",
        params![3],
    )?;
    Ok(())
}

fn migrate_v3_to_v4(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(include_str!("../../migrations/v4_fix_credentials_fk.sql"))?;
    conn.execute(
        "UPDATE vault_meta SET value = ?1 WHERE key = 'schema_version'",
        params![4],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn dummy_key() -> [u8; 32] { [0xAAu8; 32] }

    #[test]
    fn test_create_and_open_vault() {
        let f = NamedTempFile::new().unwrap();
        let conn = open_vault(f.path(), &dummy_key()).unwrap();
        for table in &[
            "vault_meta", "users", "fido2_credentials", "otp_config",
            "folders", "credentials", "asset_holder", "audit_log", "pqc_credentials",
        ] {
            let n: u32 = conn.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                params![table],
                |r| r.get(0),
            ).unwrap();
            assert_eq!(n, 1, "table '{table}' missing from schema");
        }
    }

    #[test]
    fn test_schema_version_is_current_after_migration() {
        let f = NamedTempFile::new().unwrap();
        let _ = open_vault(f.path(), &dummy_key()).unwrap();
        let conn = open_vault(f.path(), &dummy_key()).unwrap();
        let v: u32 = conn.query_row(
            "SELECT value FROM vault_meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        ).unwrap();
        assert_eq!(v, CURRENT_SCHEMA_VERSION);
    }

    /// v4 rebuilds credentials to drop the dangling FK left by v2's rename of
    /// folders → folders_legacy. After the full migration chain, the credentials
    /// table must NOT reference folders_legacy in its schema; otherwise INSERTs
    /// fail with "no such table: main.folders_legacy" once the Rust code in
    /// state::migrate_data_to_v2 drops folders_legacy.
    #[test]
    fn test_credentials_fk_does_not_reference_folders_legacy() {
        let f = NamedTempFile::new().unwrap();
        let conn = open_vault(f.path(), &dummy_key()).unwrap();
        let sql: String = conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='credentials'",
            [],
            |r| r.get(0),
        ).unwrap();
        assert!(!sql.contains("folders_legacy"),
            "credentials.folder_id FK still references folders_legacy: {sql}");
    }
}
