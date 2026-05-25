-- migration v4: Rebuild credentials table to drop dangling FK to folders_legacy.
--
-- Background: v2_defense_in_depth.sql does `ALTER TABLE folders RENAME TO folders_legacy`.
-- On SQLite >= 3.26 the rename auto-rewrites FK references in dependent tables, so
-- credentials.folder_id ends up `REFERENCES folders_legacy(id)`. The Rust code in
-- migrate_data_to_v2 (state.rs) later DROPs folders_legacy, leaving credentials
-- with a dangling FK. Any subsequent INSERT INTO credentials with foreign_keys=ON
-- fails with `no such table: main.folders_legacy`.
--
-- Fix: rebuild credentials with the correct FK to folders(id). Data is preserved
-- via INSERT ... SELECT. Indexes are recreated. Runs under foreign_keys=OFF for
-- the duration of the swap (re-enabled by db::open_vault after migrations).

PRAGMA foreign_keys = OFF;

CREATE TABLE credentials_new (
  id             TEXT PRIMARY KEY,
  folder_id      TEXT REFERENCES folders(id),
  encrypted_dek  BLOB NOT NULL,
  dek_nonce      BLOB NOT NULL,
  ciphertext     BLOB NOT NULL,
  ct_nonce       BLOB NOT NULL,
  ct_aad         BLOB NOT NULL,
  schema_version INTEGER DEFAULT 1,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL,
  service_hash   TEXT,
  url_hash       TEXT,
  username_hash  TEXT,
  tags_hash      TEXT
);

INSERT INTO credentials_new (
  id, folder_id, encrypted_dek, dek_nonce, ciphertext, ct_nonce, ct_aad,
  schema_version, created_at, updated_at,
  service_hash, url_hash, username_hash, tags_hash
)
SELECT
  id, folder_id, encrypted_dek, dek_nonce, ciphertext, ct_nonce, ct_aad,
  schema_version, created_at, updated_at,
  service_hash, url_hash, username_hash, tags_hash
FROM credentials;

DROP INDEX IF EXISTS idx_credentials_folder;
DROP TABLE credentials;
ALTER TABLE credentials_new RENAME TO credentials;
CREATE INDEX IF NOT EXISTS idx_credentials_folder ON credentials(folder_id);

PRAGMA foreign_keys = ON;
